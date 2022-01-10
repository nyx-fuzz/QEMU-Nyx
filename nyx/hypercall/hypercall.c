/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include "qemu/osdep.h"
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "qemu-common.h"
#include "exec/memory.h"
#include "qemu/main-loop.h"


#include "sysemu/kvm_int.h"
#include "sysemu/runstate.h"
#include "sysemu/cpus.h"

#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "sysemu/cpus.h"

#include "sysemu/hw_accel.h"


#include "nyx/pt.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/memory_access.h"
#include "nyx/interface.h"
#include "nyx/printk.h"
#include "nyx/debug.h"
#include "nyx/synchronization.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/kvm_nested.h"
#include "nyx/state.h"
#include "sysemu/runstate.h"
#include "nyx/helpers.h"
#include "nyx/nested_hypercalls.h"
#include "nyx/fast_vm_reload_sync.h"

#include "nyx/redqueen.h"
#include "nyx/hypercall/configuration.h"

//#define DEBUG_HPRINTF

bool reload_mode_temp = false;
bool notifiers_enabled = false;
//uint32_t hprintf_counter = 0;

bool hypercall_enabled = false;
void* program_buffer = NULL;
char info_buffer[INFO_SIZE];
char hprintf_buffer[HPRINTF_SIZE];

static bool init_state = true;

void skip_init(void){
	init_state = false;
}

bool pt_hypercalls_enabled(void){
	return hypercall_enabled;
}

void pt_setup_enable_hypercalls(void){
	hypercall_enabled = true;
}

void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end){
	debug_fprintf(stderr, "--> %s\n", __func__);
	if (filter_id < INTEL_PT_MAX_RANGES){

		GET_GLOBAL_STATE()->pt_ip_filter_configured[filter_id] = true;
		GET_GLOBAL_STATE()->pt_ip_filter_a[filter_id] = start;
		GET_GLOBAL_STATE()->pt_ip_filter_b[filter_id] = end;

	}
}

void hypercall_commit_filter(void){
}

bool setup_snapshot_once = false;


void pt_setup_program(void* ptr){
	program_buffer = ptr;
}


bool handle_hypercall_kafl_next_payload(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//fprintf(stderr, "%s\n", __func__);
/*
	kvm_arch_get_registers(cpu);
	X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;

	printf("%s: exception_injected: %d\n", __func__, env->exception_injected);
*/
	if(hypercall_enabled){
		if (init_state){
			set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 2);
			//fprintf(stderr, "--------------------\n");
			synchronization_lock();

		} else {
			if(!setup_snapshot_once){ 
				//pt_reset_bitmap();

				if (GET_GLOBAL_STATE()->pt_trace_mode){
					fprintf(stderr, "[QEMU-Nyx] coverage mode: Intel-PT (KVM-Nyx and libxdc)\n");
				}
				else{
					fprintf(stderr, "[QEMU-Nyx] coverage mode: compile-time instrumentation\n");
				}

				coverage_bitmap_reset();
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP);
				setup_snapshot_once = true;

				for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
					//printf("=> %d\n", i);
					//if(filter_enabled[i]){
					if(GET_GLOBAL_STATE()->pt_ip_filter_configured[i]){
						pt_enable_ip_filtering(cpu, i, true, false);
					}
				}
				pt_init_decoder(cpu);

				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_ROOT);

				//printf("DONE!\n");
				/*
				qemu_mutex_lock_iothread();
				QEMU_PT_PRINTF(CORE_PREFIX, "...GOOOOOO!!!!");
				fast_reload_restore(get_fast_reload_snapshot());
				QEMU_PT_PRINTF(CORE_PREFIX, "...DONE!!!!");
				qemu_mutex_unlock_iothread();
				*/
				GET_GLOBAL_STATE()->in_fuzzing_mode = true;
				set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 3);

				//sigprof_enabled = true;
				//reset_timeout_detector(&GET_GLOBAL_STATE()->timeout_detector);
			}
			else{
				//set_illegal_payload();
				synchronization_lock();
				reset_timeout_detector(&GET_GLOBAL_STATE()->timeout_detector);
				GET_GLOBAL_STATE()->in_fuzzing_mode = true;


				//printf("RIP => %lx\n", get_rip(cpu));
				return true;
			}
		}
	}
	return false;
}

bool acquire_print_once_bool = true;
bool release_print_once_bool = true;

static void acquire_print_once(CPUState *cpu){
	if(acquire_print_once_bool){
		acquire_print_once_bool = false;
		kvm_arch_get_registers(cpu);
		//X86CPU *x86_cpu = X86_CPU(cpu);
		//CPUX86State *env = &x86_cpu->env;
		debug_fprintf(stderr,  "handle_hypercall_kafl_acquire at:%lx\n", get_rip(cpu));
		//disassemble_at_rip(STDERR_FILENO, get_rip(cpu), cpu, env->cr[3]);
	}
}

void handle_hypercall_kafl_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//return;
	if(hypercall_enabled){
		if (!init_state){
			acquire_print_once(cpu);
			//init_det_filter();
			synchronization_enter_fuzzing_loop(cpu);
			/*
			if (pt_enable(cpu, false) == 0){
				cpu->pt_enabled = true;
			}
			*/
		}
	}
}

static void handle_hypercall_get_payload(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	debug_printf("------------ %s\n", __func__);
	if(hypercall_enabled && !setup_snapshot_once){
			QEMU_PT_PRINTF(CORE_PREFIX, "Payload Address:\t%lx", hypercall_arg);
			kvm_arch_get_registers(cpu);	
			CPUX86State *env = &(X86_CPU(cpu))->env;
			GET_GLOBAL_STATE()->parent_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
			QEMU_PT_PRINTF(CORE_PREFIX, "Payload CR3:\t%lx", (uint64_t)GET_GLOBAL_STATE()->parent_cr3 );
			//print_48_paging2(GET_GLOBAL_STATE()->parent_cr3);

			if(hypercall_arg&0xFFF){
				fprintf(stderr, "[QEMU-Nyx] Error: Payload buffer is not page-aligned! (0x%lx)\n", hypercall_arg);
				abort();
			}

			remap_payload_buffer(hypercall_arg, cpu);
			set_payload_buffer(hypercall_arg);
	}
}

static void set_return_value(CPUState *cpu, uint64_t return_value){
	kvm_arch_get_registers(cpu);	
	CPUX86State *env = &(X86_CPU(cpu))->env;
	env->regs[R_EAX] =  return_value;
	kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);	
}

static void handle_hypercall_kafl_req_stream_data(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	static uint8_t req_stream_buffer[0x1000];

	kvm_arch_get_registers(cpu);	
	/* address has to be page aligned */
	if((hypercall_arg&0xFFF) != 0){
		debug_fprintf(stderr, "%s: ERROR -> address is not page aligned!\n", __func__);
		set_return_value(cpu, 0xFFFFFFFFFFFFFFFFUL);
	}
	else{
		read_virtual_memory(hypercall_arg, (uint8_t*)req_stream_buffer, 0x100, cpu);
		uint64_t bytes = sharedir_request_file(GET_GLOBAL_STATE()->sharedir, (const char *)req_stream_buffer, req_stream_buffer);
		if(bytes != 0xFFFFFFFFFFFFFFFFUL){
			write_virtual_memory(hypercall_arg, (uint8_t*)req_stream_buffer, bytes, cpu);
		}
		set_return_value(cpu, bytes);
	}
}

typedef struct req_data_bulk_s{
	char file_name[256];
	uint64_t num_addresses;
	uint64_t addresses[479];
} req_data_bulk_t;

static void handle_hypercall_kafl_req_stream_data_bulk(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	static uint8_t req_stream_buffer[0x1000];
	//static uint64_t addresses[512];
	req_data_bulk_t req_data_bulk_data;

	kvm_arch_get_registers(cpu);	
	/* address has to be page aligned */
	if((hypercall_arg&0xFFF) != 0){
		debug_fprintf(stderr, "%s: ERROR -> address is not page aligned!\n", __func__);
		set_return_value(cpu, 0xFFFFFFFFFFFFFFFFUL);
	}
	else{
		uint64_t bytes = 0;
		read_virtual_memory(hypercall_arg, (uint8_t*)&req_data_bulk_data, 0x1000, cpu);

		assert(req_data_bulk_data.num_addresses <= 479);
		for(int i = 0; i < req_data_bulk_data.num_addresses; i++){
			uint64_t ret_val = sharedir_request_file(GET_GLOBAL_STATE()->sharedir, (const char *)req_data_bulk_data.file_name, req_stream_buffer);
			if(ret_val != 0xFFFFFFFFFFFFFFFFUL){
				bytes += ret_val;
				write_virtual_memory((uint64_t)req_data_bulk_data.addresses[i], (uint8_t*)req_stream_buffer, ret_val, cpu);
			}
			else if(ret_val == 0){
				break;
			}
			else{
				bytes = 0xFFFFFFFFFFFFFFFFUL;
				break;
			}
			
		}

		//fprintf(stderr, "%s -> %d\n", __func__, bytes);
		set_return_value(cpu, bytes);
	}
}


static void handle_hypercall_kafl_range_submit(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	uint64_t buffer[3];
	read_virtual_memory(hypercall_arg, (uint8_t*)&buffer, sizeof(buffer), cpu);

	if(buffer[2] >= 2){
		QEMU_PT_PRINTF(CORE_PREFIX, "%s: illegal range=%ld\n", __func__, buffer[2]);
		return;
	}

	if(GET_GLOBAL_STATE()->pt_ip_filter_configured[buffer[2]]){
			QEMU_PT_PRINTF(CORE_PREFIX, "Ignoring agent-provided address ranges (abort reason: 1) - %d", buffer[2]);
		return;
	}

	if (buffer[0] != 0 && buffer[1] != 0 ){
		GET_GLOBAL_STATE()->pt_ip_filter_a[buffer[2]] = buffer[0];
		GET_GLOBAL_STATE()->pt_ip_filter_b[buffer[2]] = buffer[1];
		GET_GLOBAL_STATE()->pt_ip_filter_configured[buffer[2]] = true;
		QEMU_PT_PRINTF(CORE_PREFIX, "Configuring agent-provided address ranges:");
		QEMU_PT_PRINTF(CORE_PREFIX, "\tIP%d: %lx-%lx [ENABLED]", buffer[2], GET_GLOBAL_STATE()->pt_ip_filter_a[buffer[2]], GET_GLOBAL_STATE()->pt_ip_filter_b[buffer[2]]);
	}
	else{
		QEMU_PT_PRINTF(CORE_PREFIX, "Ignoring agent-provided address ranges (abort reason: 2)");	
	}

}

static void handle_hypercall_get_program(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){

		//fprintf(stderr, "%s\n", __func__);	
	/*
	return;

	if(!get_fast_reload_snapshot()->qemu_state){
		fast_reload_create_in_memory(get_fast_reload_snapshot(), true);
	}
	*/
/*
	qemu_mutex_lock_iothread();
	fast_reload_restore(get_fast_reload_snapshot());

	qemu_mutex_unlock_iothread();
	return;
	*/
	kvm_arch_get_registers(cpu);
	X86CPU *x86_cpu = X86_CPU(cpu);
		CPUX86State *env = &x86_cpu->env;

	if(hypercall_enabled){
		if(program_buffer){

			if (env->cr[4] & CR4_PAE_MASK) {
        if (env->hflags & HF_LMA_MASK) {
					//fprintf(stderr, "IN 64Bit MODE\n");
				}
				else{
					debug_fprintf(stderr, "IN 32Bit PAE MODE\n");
					abort();
				}
			}
			else{
				debug_fprintf(stderr, "IN 32Bit MODE\n");
				abort();
			}
			
			//print_48_paging2(env->cr[3]);
			write_virtual_memory(hypercall_arg, program_buffer, PROGRAM_SIZE, cpu);
		}
	}
}


static void release_print_once(CPUState *cpu){
	if(release_print_once_bool){
		release_print_once_bool = false;
		kvm_arch_get_registers(cpu);
		//X86CPU *x86_cpu = X86_CPU(cpu);
		//CPUX86State *env = &x86_cpu->env;
		debug_fprintf(stderr,  "handle_hypercall_kafl_release at:%lx\n", get_rip(cpu));
		//disassemble_at_rip(STDERR_FILENO, get_rip(cpu), cpu, env->cr[3]);
	}
}

void handle_hypercall_kafl_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//fprintf(stderr, "%s\n", __func__);
	if(hypercall_enabled){
		if (init_state){
			init_state = false;	

			

			//hypercall_snd_char(KAFL_PROTO_RELEASE);
			//QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_RELEASE");

		} else {


			synchronization_disable_pt(cpu);
			release_print_once(cpu);
			/*
			if(reload_mode || reload_mode_temp){
				qemu_mutex_lock_iothread();
				//QEMU_PT_PRINTF(CORE_PREFIX, "...GOOOOOO 2 !!!!");
				fast_reload_restore(get_fast_reload_snapshot());
				//QEMU_PT_PRINTF(CORE_PREFIX, "...DONE 2 !!!!");
				qemu_mutex_unlock_iothread();
			}
			*/
		}
	}
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int err;
};

void handle_hypercall_kafl_mtf(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//assert(false);
	kvm_arch_get_registers_fast(cpu);

	debug_fprintf(stderr, "%s --> %lx\n", __func__, get_rip(cpu));

	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_MTF);

	kvm_remove_all_breakpoints(cpu);
	kvm_insert_breakpoint(cpu, GET_GLOBAL_STATE()->dump_page_addr, 1, 1);
	kvm_update_guest_debug(cpu, 0);

	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3, GET_GLOBAL_STATE()->pt_c3_filter);
	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

void handle_hypercall_kafl_page_dump_bp(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg, uint64_t page){
	//fprintf(stderr, "--> %s\n", __func__);
	kvm_arch_get_registers_fast(cpu);

	debug_fprintf(stderr, "%s --> %lx\n", __func__, get_rip(cpu));

	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_MTF);

	bool success = false;
	//fprintf(stderr, "page_cache_fetch = %lx\n", page_cache_fetch(GET_GLOBAL_STATE()->page_cache, page, &success, false));
	page_cache_fetch(GET_GLOBAL_STATE()->page_cache, page, &success, false);
	if(success){

		debug_fprintf(stderr, "%s: SUCCESS: %d\n", __func__, success);
		kvm_remove_all_breakpoints(cpu);
		kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);

	}
	else{
		debug_fprintf(stderr, "%s: FAIL: %d\n", __func__, success);
		//assert(false);

		kvm_remove_all_breakpoints(cpu);

		kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
		kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
	}

}

static inline void set_page_dump_bp(CPUState *cpu, uint64_t cr3, uint64_t addr){
		
	debug_fprintf(stderr, "\n\n%s %lx %lx\n\n", __func__, cr3, addr);
	kvm_remove_all_breakpoints(cpu);
	kvm_insert_breakpoint(cpu, addr, 1, 1);
	kvm_update_guest_debug(cpu, 0);

	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3, cr3);
	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

static void handle_hypercall_kafl_cr3(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(hypercall_enabled){
		//QEMU_PT_PRINTF(CORE_PREFIX, "CR3 address:\t\t%lx", hypercall_arg);
		pt_set_cr3(cpu, hypercall_arg & 0xFFFFFFFFFFFFF000ULL, false);
		if(GET_GLOBAL_STATE()->dump_page){
			set_page_dump_bp(cpu, hypercall_arg & 0xFFFFFFFFFFFFF000ULL, GET_GLOBAL_STATE()->dump_page_addr);
		}
	}
}

static void handle_hypercall_kafl_submit_panic(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(hypercall_enabled){
		QEMU_PT_PRINTF(CORE_PREFIX, "Panic address:\t%lx", hypercall_arg);
		if(notifiers_enabled){
			write_virtual_memory(hypercall_arg, (uint8_t*)PANIC_PAYLOAD, PAYLOAD_BUFFER_SIZE, cpu);
		}
	}
}

static void handle_hypercall_kafl_submit_kasan(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(hypercall_enabled){
		QEMU_PT_PRINTF(CORE_PREFIX, "kASAN address:\t%lx", hypercall_arg);
		if(notifiers_enabled){
			write_virtual_memory(hypercall_arg, (uint8_t*)KASAN_PAYLOAD, PAYLOAD_BUFFER_SIZE, cpu);
		}
	}
}

//#define PANIC_DEBUG

static void handle_hypercall_kafl_panic(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	static char reason[1024];
	if(hypercall_enabled){
#ifdef PANIC_DEBUG
		if(hypercall_arg){
			//fprintf(stderr, "Panic in user mode!\n");
			//QEMU_PT_PRINTF(CORE_PREFIX, "Panic in user mode!");
		} else{
			debug_fprintf(stderr, "Panic in kernel mode!\n");
			QEMU_PT_PRINTF(CORE_PREFIX, "Panic in kernel mode!");
			//assert(0);
		}
#endif
		if(fast_reload_snapshot_exists(get_fast_reload_snapshot())){

			if(hypercall_arg & 0x8000000000000000ULL){

				reason[0] = '\x00';

				uint64_t address = hypercall_arg & 0x7FFFFFFFFFFFULL;
				uint64_t signal = (hypercall_arg & 0x7800000000000ULL) >> 47;

				snprintf(reason, 1024, "PANIC IN USER MODE (SIG: %d\tat 0x%lx)\n", (uint8_t)signal, address);
				set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, reason, strlen(reason));
			}
			else{
				switch(hypercall_arg){
					case 0:
						set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, (char*)"PANIC IN KERNEL MODE!\n", strlen("PANIC IN KERNEL MODE!\n"));
						break;
					case 1:
						set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, (char*)"PANIC IN USER MODE!\n", strlen("PANIC IN USER MODE!\n"));
						break;
					default:
						set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, (char*)"???\n", strlen("???\n"));
						break;
				}

			}
			synchronization_lock_crash_found();
			//synchronization_stop_vm_crash(cpu);
		} else{
			fprintf(stderr, "Panic detected during initialization of stage 1 or stage 2 loader (%lx)\n", hypercall_arg);
			abort();
			//hypercall_snd_char(KAFL_PROTO_CRASH);
			QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_CRASH");

		}
	}
}

static double get_time(void){
	struct timeval t;
	struct timezone tzp;
	gettimeofday(&t, &tzp);
	return t.tv_sec + t.tv_usec*1e-6;
}

static void print_time_diff(int iterations){

	static bool init = true;
	static double start_time = 0.0;
	static double end_time = 0.0;

	if(init){
		init = false;
		printf("start time is zero!\n");
		start_time = get_time();
	}
	else{
		end_time = get_time();
		double elapsed_time = end_time - start_time;
		printf("Done in %f seconds\n", elapsed_time);
		printf("Performance: %f\n", iterations/elapsed_time);
		start_time = get_time();
	}
}

static void meassure_performance(void){
	static int perf_counter = 0;
	if ((perf_counter%1000) == 0){
		//printf("perf_counter -> %d \n", perf_counter);
		print_time_diff(1000);
	}
	perf_counter++;
}
static void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//X86CPU *x86_cpu = X86_CPU(cpu);
	//CPUX86State *env = &x86_cpu->env;
	static bool first = true;

	//printf("CALLED %s: %lx\n", __func__, hypercall_arg);
	switch(hypercall_arg&0xFFF){
		case 0: /* create root snapshot */
			if(!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_ROOT_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_ROOT);
			}
			break;
		case 1: /* create tmp snapshot */
			//printf("%s: create tmp...(RIP: %lx)\n", __func__, get_rip(cpu));
			if(!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_TMP);
			}
			break;
		case 2: /* load root snapshot (+ discard tmp snapshot) */
			//printf("%s: load root...(RIP: %lx)\n", __func__, get_rip(cpu));
			if(fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				reload_request_discard_tmp(GET_GLOBAL_STATE()->reload_state);
			}
			request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_ROOT);
			//meassure_performance();
			break;
		case 3: /* load tmp snapshot */
			if(fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_TMP);
				//meassure_performance();
			}
			break;
		case 5: // firefox debug hypercall
			if(first){
				first = false;
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_ROOT);
				//request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_TMP);

				break;
			}
			else{
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_ROOT);
				break;
			}
		/*
		case 6:
			printf("%s: -> request to add 0x%lx to block-list\n", __func__, hypercall_arg&(~0xFFF));
			CPUX86State *env = &(X86_CPU(cpu))->env;
    	kvm_arch_get_registers_fast(cpu);
    	hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cpu, env->cr[3], hypercall_arg&(~0xFFF));
	    fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);

			break;
	 */
		default:
			abort();
	}
}

static void handle_hypercall_kafl_create_tmp_snapshot(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//X86CPU *x86_cpu = X86_CPU(cpu);
	//CPUX86State *env = &x86_cpu->env;
	if(!fast_reload_tmp_created(get_fast_reload_snapshot())){

		/* decode PT data */
		pt_disable(qemu_get_cpu(0), false);
		pt_sync();

		/*
		kvm_arch_get_registers(cpu);
		kvm_cpu_synchronize_state(cpu);
		//fprintf(stderr, "%s: CREATE at %lx\n", __func__, get_rip(cpu));

		//env->eip -= 3; // vmcall size 
		//kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
		fast_reload_create_tmp_snapshot(get_fast_reload_snapshot());
		//kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);

		qemu_mutex_lock_iothread();
		fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();

		*/



		request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_TMP); //_TMP_FIX_RIP);
					
		set_tmp_snapshot_created(GET_GLOBAL_STATE()->auxilary_buffer, 1);
		//handle_hypercall_kafl_acquire(run, cpu);
		//fprintf(stderr, "%s: CREATE DONE at %lx\n", __func__, get_rip(cpu));

		handle_hypercall_kafl_release(run, cpu, (uint64_t)run->hypercall.args[0]);
	}
	else{
		//fprintf(stderr, "%s: LOAD Continue at %lx\n", __func__, get_rip(cpu));
		//fprintf(stderr, "%s: LOAD at %lx\n", __func__, get_rip(cpu));

		/*
		qemu_mutex_lock_iothread();
		fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();

		fprintf(stderr, "%s: LOAD Continue at %lx\n", __func__, get_rip(cpu));
		*/

		//handle_hypercall_kafl_acquire(run, cpu);
	}
}

static void handle_hypercall_kafl_panic_extended(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
		if(fast_reload_snapshot_exists(get_fast_reload_snapshot())){
			read_virtual_memory(hypercall_arg, (uint8_t*)hprintf_buffer, HPRINTF_SIZE, cpu);
			set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, hprintf_buffer, strlen(hprintf_buffer));
			synchronization_lock_crash_found();
		} else{
      read_virtual_memory(hypercall_arg, (uint8_t*)hprintf_buffer, HPRINTF_SIZE, cpu);
			fprintf(stderr, "Panic detected during initialization of stage 1 or stage 2 loader\n");
			fprintf(stderr, "REASON:\n%s\n", hprintf_buffer);
			abort();
			QEMU_PT_PRINTF(CORE_PREFIX, "Panic detected during initialization of stage 1 or stage 2 loader");
			//hypercall_snd_char(KAFL_PROTO_CRASH);
			QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_CRASH");
			//read_virtual_memory(hypercall_arg, (uint8_t*)hprintf_buffer, HPRINTF_SIZE, cpu);
			//fprintf(stderr, "-> %s\n", hprintf_buffer);
		}
}


static void handle_hypercall_kafl_kasan(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(hypercall_enabled){
#ifdef PANIC_DEBUG
		if(hypercall_arg){
			QEMU_PT_PRINTF(CORE_PREFIX, "ASan notification in user mode!");
		} else{
			QEMU_PT_PRINTF(CORE_PREFIX, "ASan notification in kernel mode!");
		}
#endif
		if(fast_reload_snapshot_exists(get_fast_reload_snapshot())){
			synchronization_lock_asan_found();
			//synchronization_stop_vm_kasan(cpu);
		} else{
			QEMU_PT_PRINTF(CORE_PREFIX, "KASAN detected during initialization of stage 1 or stage 2 loader");
			//hypercall_snd_char(KAFL_PROTO_KASAN);
			QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_KASAN");

		}
	}
}


/*
static uint64_t get_rsp(CPUState *cpu){
	kvm_arch_get_registers(cpu);
	X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;
	kvm_cpu_synchronize_state(cpu);
	return env->regs[4];
}
*/

static void handle_hypercall_kafl_lock(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){

	if(!GET_GLOBAL_STATE()->fast_reload_pre_image){
		QEMU_PT_PRINTF(CORE_PREFIX, "Skipping pre image creation (hint: set pre=on) ...");
		return;

/*

							fast_reload_create_in_memory(get_fast_reload_snapshot(), true);

qemu_mutex_lock_iothread();
	fast_reload_restore(get_fast_reload_snapshot());

	qemu_mutex_unlock_iothread();
	*/
		//return;
	}

	QEMU_PT_PRINTF(CORE_PREFIX, "Creating pre image snapshot <%s> ...", GET_GLOBAL_STATE()->fast_reload_pre_path);

	printf("Creating pre image snapshot");
	request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_PRE);
}

static void handle_hypercall_kafl_info(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(setup_snapshot_once)
		return;
		
	debug_printf("%s\n", __func__);
/*
	printf("[*] EXEC: %s\t%lx %lx\n", __func__, get_rip(cpu), get_rsp(cpu));
	hexdump_virtual_memory(get_rsp(cpu), 0x100, cpu);

	kvm_arch_get_registers(cpu);
	kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
*/
	/*
	qemu_mutex_lock_iothread();
	//fast_reload_restore((fast_reload_t*)cpu->fast_reload_snapshot);
	fast_reload_restore(get_fast_reload_snapshot());
	//kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);
	qemu_mutex_unlock_iothread();
	return;
	*/
/*
		kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);


	printf("[*] EXIT: %s\t%lx %lx\n", __func__, get_rip(cpu), get_rsp(cpu));
	hexdump_virtual_memory(get_rsp(cpu), 0x100, cpu);
*/
//	return; 

	read_virtual_memory(hypercall_arg, (uint8_t*)info_buffer, INFO_SIZE, cpu);
	FILE* info_file_fd = fopen(INFO_FILE, "w");
	fprintf(info_file_fd, "%s\n", info_buffer);
	fclose(info_file_fd);
	if(hypercall_enabled){
		//hypercall_snd_char(KAFL_PROTO_INFO);
		QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_INFO");
		abort();

	}
	qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
}

void enable_notifies(void){
	notifiers_enabled = true;
}


/*
void hprintf(char* msg){
	char file_name[256];
	if(!(hprintf_counter >= HPRINTF_LIMIT) && GET_GLOBAL_STATE()->enable_hprintf){
		if(hypercall_enabled){
			snprintf(file_name, 256, "%s.%d", HPRINTF_FILE, hprintf_counter);
			//printf("%s: %s\n", __func__, msg);
			FILE* printf_file_fd = fopen(file_name, "w");
			fprintf(printf_file_fd, "%s", msg);
			fclose(printf_file_fd);
			//hypercall_snd_char(KAFL_PROTO_PRINTF);
			QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_PRINTF");

		}
		hprintf_counter++;

	}		
}
*/

static void handle_hypercall_kafl_printf(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//fprintf(stderr, "%s\n", __func__);
	//if( /* !(hprintf_counter >= HPRINTF_LIMIT) && */ GET_GLOBAL_STATE()->enable_hprintf){ // && !GET_GLOBAL_STATE()->in_fuzzing_mode){
		read_virtual_memory(hypercall_arg, (uint8_t*)hprintf_buffer, HPRINTF_SIZE, cpu);
		//hprintf(hprintf_buffer);
#ifdef DEBUG_HPRINTF
		fprintf(stderr, "%s %s\n", __func__, hprintf_buffer);
#else
		set_hprintf_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, hprintf_buffer, strnlen(hprintf_buffer, HPRINTF_SIZE)+1);
		synchronization_lock();
#endif
	//}
}


static void handle_hypercall_kafl_printk(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(!notifiers_enabled){
		if (hypercall_enabled && GET_GLOBAL_STATE()->enable_hprintf){
			if(kafl_linux_printk(cpu)){
				handle_hypercall_kafl_panic(run, cpu, (uint64_t)run->hypercall.args[0]);
			}
		}
	}
}

static void handle_hypercall_kafl_printk_addr(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(!notifiers_enabled){
		debug_printf("%s\n", __func__);
		debug_printf("%lx\n", hypercall_arg);
		write_virtual_memory(hypercall_arg, (uint8_t*)PRINTK_PAYLOAD, PRINTK_PAYLOAD_SIZE, cpu);
		debug_printf("Done\n");
	}		
}

static void handle_hypercall_kafl_user_range_advise(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	kAFL_ranges* buf = malloc(sizeof(kAFL_ranges));

	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		buf->ip[i] = GET_GLOBAL_STATE()->pt_ip_filter_a[i]; 
		buf->size[i] = (GET_GLOBAL_STATE()->pt_ip_filter_b[i]-GET_GLOBAL_STATE()->pt_ip_filter_a[i]);
		buf->enabled[i] = (uint8_t)GET_GLOBAL_STATE()->pt_ip_filter_configured[i];
	}

	write_virtual_memory(hypercall_arg, (uint8_t *)buf, sizeof(kAFL_ranges), cpu);
	free(buf);
}

static void handle_hypercall_kafl_user_submit_mode(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//printf("%s\n", __func__);
	switch(hypercall_arg){
		case KAFL_MODE_64:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in KAFL_MODE_64 ...");
			GET_GLOBAL_STATE()->disassembler_word_width = 64;
			break;
		case KAFL_MODE_32:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in KAFL_MODE_32 ...");
			GET_GLOBAL_STATE()->disassembler_word_width = 32;
			break;
		case KAFL_MODE_16:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in KAFL_MODE_16 ...");
			GET_GLOBAL_STATE()->disassembler_word_width = 16;
			abort(); /* not implemented in this version (due to hypertrash hacks) */
			break;
		default:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in unkown mode...");
			GET_GLOBAL_STATE()->disassembler_word_width = 0;
			abort(); /* not implemented in this version (due to hypertrash hacks) */
			break;
	}
}

bool handle_hypercall_kafl_hook(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	X86CPU *cpux86 = X86_CPU(cpu);
    CPUX86State *env = &cpux86->env;

	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (GET_GLOBAL_STATE()->redqueen_state && (env->eip >= GET_GLOBAL_STATE()->pt_ip_filter_a[i]) && (env->eip <= GET_GLOBAL_STATE()->pt_ip_filter_b[i])){
			handle_hook(GET_GLOBAL_STATE()->redqueen_state);
			return true;
		}else if (cpu->singlestep_enabled && (GET_GLOBAL_STATE()->redqueen_state)->singlestep_enabled){
			handle_hook(GET_GLOBAL_STATE()->redqueen_state);
			return true;
    }
	}
	return false;
}

static void handle_hypercall_kafl_user_abort(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	read_virtual_memory(hypercall_arg, (uint8_t*)hprintf_buffer, HPRINTF_SIZE, cpu);
	set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, hprintf_buffer, strlen(hprintf_buffer));
	synchronization_lock();
}

void pt_enable_rqi(CPUState *cpu){
	reload_mode_temp = true;
	//cpu->redqueen_enable_pending = true;
	GET_GLOBAL_STATE()->redqueen_enable_pending = true;
}

void pt_disable_rqi(CPUState *cpu){
	reload_mode_temp = false;
	//cpu->redqueen_disable_pending = true;
	GET_GLOBAL_STATE()->redqueen_disable_pending = true;
	GET_GLOBAL_STATE()->redqueen_instrumentation_mode = REDQUEEN_NO_INSTRUMENTATION;
	//cpu->redqueen_instrumentation_mode = REDQUEEN_NO_INSTRUMENTATION;
}

void pt_set_enable_patches_pending(CPUState *cpu){
	GET_GLOBAL_STATE()->patches_enable_pending = true;
}

void pt_set_redqueen_instrumentation_mode(CPUState *cpu, int redqueen_mode){
  //cpu->redqueen_instrumentation_mode = redqueen_mode;
	GET_GLOBAL_STATE()->redqueen_instrumentation_mode = redqueen_mode;
}

void pt_set_redqueen_update_blacklist(CPUState *cpu, bool newval){
  assert(!newval || !GET_GLOBAL_STATE()->redqueen_update_blacklist);
  //cpu->redqueen_update_blacklist = newval;
	GET_GLOBAL_STATE()->redqueen_update_blacklist = newval;
}

void pt_set_disable_patches_pending(CPUState *cpu){
	GET_GLOBAL_STATE()->patches_disable_pending = true;
}

void pt_enable_rqi_trace(CPUState *cpu){
	if (GET_GLOBAL_STATE()->redqueen_state){
		redqueen_set_trace_mode(GET_GLOBAL_STATE()->redqueen_state);
	}
}

void pt_disable_rqi_trace(CPUState *cpu){
	if (GET_GLOBAL_STATE()->redqueen_state){
		redqueen_unset_trace_mode(GET_GLOBAL_STATE()->redqueen_state);
		return;
	}
}

static void handle_hypercall_kafl_dump_file(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){

	/* TODO: check via aux buffer if we should allow this hypercall during fuzzing */
	/*
	if(GET_GLOBAL_STATE()->in_fuzzing_mode){
		return;
	}
	*/

	char filename[256] = {0};

	uint64_t vaddr = hypercall_arg;
	kafl_dump_file_t file_obj;
	memset((void*)&file_obj, 0, sizeof(kafl_dump_file_t));


	if(read_virtual_memory(vaddr, (uint8_t*)&file_obj, sizeof(kafl_dump_file_t), cpu)){

		void* page = malloc(0x1000);
	
		read_virtual_memory(file_obj.file_name_str_ptr, (uint8_t*)&filename, sizeof(char)*256, cpu);
		filename[255] = 0;

    char* base_name = basename(filename);		
		char* host_path = NULL;

		assert(asprintf(&host_path, "%s/dump/%s", GET_GLOBAL_STATE()->workdir_path , base_name) != -1);
		//fprintf(stderr, "dumping file %s -> %s (bytes %ld) in append_mode=%d\n", base_name, host_path, file_obj.bytes, file_obj.append);

    FILE* f = NULL;

		if(file_obj.append){
	  	f = fopen(host_path, "a+");
		}
		else{
    	f = fopen(host_path, "w+");
		}

		int32_t bytes = file_obj.bytes;
		uint32_t pos = 0;

		while(bytes > 0){

			if(bytes >= 0x1000){
				read_virtual_memory(file_obj.data_ptr+pos, (uint8_t*)page, 0x1000, cpu);
				fwrite(page, 1, 0x1000, f);
			}
			else{
				read_virtual_memory(file_obj.data_ptr+pos, (uint8_t*)page, bytes, cpu);
				fwrite(page, 1, bytes, f);
			}

			bytes -= 0x1000;
			pos += 0x1000;
		}


		fclose(f);
		free(host_path);
		free(page);
		
	}
}

static void handle_hypercall_kafl_persist_page_past_snapshot(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	CPUX86State *env = &(X86_CPU(cpu))->env;
	kvm_arch_get_registers_fast(cpu);
	hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cpu, env->cr[3], hypercall_arg&(~0xFFF), NULL);
	assert(phys_addr != 0xffffffffffffffffULL);
	fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
}

int handle_kafl_hypercall(struct kvm_run *run, CPUState *cpu, uint64_t hypercall, uint64_t arg){
	int ret = -1;
	//fprintf(stderr, "%s -> %ld\n", __func__, hypercall);
	switch(hypercall){
		case KVM_EXIT_KAFL_ACQUIRE:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_ACQUIRE\n");
			handle_hypercall_kafl_acquire(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_GET_PAYLOAD:
			// = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_GET_PAYLOAD\n");
			handle_hypercall_get_payload(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_GET_PROGRAM:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_GET_PROGRAM\n");
			handle_hypercall_get_program(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_RELEASE:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_RELEASE\n");
			handle_hypercall_kafl_release(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_SUBMIT_CR3:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_SUBMIT_CR3\n");
			handle_hypercall_kafl_cr3(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_SUBMIT_PANIC:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_SUBMIT_PANIC\n");
			handle_hypercall_kafl_submit_panic(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_SUBMIT_KASAN:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_SUBMIT_KASAN\n");
			handle_hypercall_kafl_submit_kasan(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_PANIC:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_PANIC\n");
			handle_hypercall_kafl_panic(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_KASAN:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_KASAN\n");
			handle_hypercall_kafl_kasan(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_LOCK:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_LOCK\n");
			handle_hypercall_kafl_lock(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_INFO:
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_INFO\n");
			handle_hypercall_kafl_info(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_NEXT_PAYLOAD:
			//timeout_reload_pending = false;  
			//fprintf(stderr, "KVM_EXIT_KAFL_NEXT_PAYLOAD\n");                                                                                                                                   
			handle_hypercall_kafl_next_payload(run, cpu, arg);                                                                                                                    
			ret = 0;                                                                                                                                                         
			break;						
		case KVM_EXIT_KAFL_PRINTF:			
			//timeout_reload_pending = false;
			//fprintf(stderr, "KVM_EXIT_KAFL_PRINTF\n");                                                                                                                                  
			handle_hypercall_kafl_printf(run, cpu, arg);                                                                                                                    
			ret = 0;                                                                                                                                                         
			break;       
		case KVM_EXIT_KAFL_PRINTK_ADDR:   
			//timeout_reload_pending = false;                                                                                                                                  
			handle_hypercall_kafl_printk_addr(run, cpu, arg);                                                                                                                    
			ret = 0;                                                                                                                                                         
			break;			
		case KVM_EXIT_KAFL_PRINTK:      
			//timeout_reload_pending = false;                                                                                                                               
			handle_hypercall_kafl_printk(run, cpu, arg);                                                                                                                    
			ret = 0;                                                                                                                                                         
			break;

		/* user space only exit reasons */
		case KVM_EXIT_KAFL_USER_RANGE_ADVISE:
			//timeout_reload_pending = false;
			handle_hypercall_kafl_user_range_advise(run, cpu, arg);
			ret = 0;  
			break;
		case KVM_EXIT_KAFL_USER_SUBMIT_MODE:
			//timeout_reload_pending = false;
			handle_hypercall_kafl_user_submit_mode(run, cpu, arg);
			ret = 0;  
			break;
		case KVM_EXIT_KAFL_USER_FAST_ACQUIRE:
			//timeout_reload_pending = false;
			if(handle_hypercall_kafl_next_payload(run, cpu, arg)){
					handle_hypercall_kafl_cr3(run, cpu, arg);   
					handle_hypercall_kafl_acquire(run, cpu, arg);
			}
			ret = 0;  
			break;
		case KVM_EXIT_KAFL_TOPA_MAIN_FULL:
			//timeout_reload_pending = false;
			//fprintf(stderr, "pt_handle_overflow\n");
			pt_handle_overflow(cpu);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_USER_ABORT:
			//timeout_reload_pending = false;
			handle_hypercall_kafl_user_abort(run, cpu, arg);
			ret = 0;  
			break;
		case KVM_EXIT_KAFL_NESTED_CONFIG:
			//timeout_reload_pending = false;
			handle_hypercall_kafl_nested_config(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_NESTED_PREPARE:
			//timeout_reload_pending = false;
			handle_hypercall_kafl_nested_prepare(run, cpu, arg);
			ret = 0;
			break;

		case KVM_EXIT_KAFL_NESTED_ACQUIRE:
			//timeout_reload_pending = false;
			handle_hypercall_kafl_nested_acquire(run, cpu, arg);
			ret = 0;
			break;

		case KVM_EXIT_KAFL_NESTED_RELEASE:
			//timeout_reload_pending = false;
			//KVM_EXIT_KAFL_NESTED_RELEASE_GOTO:
			handle_hypercall_kafl_nested_release(run, cpu, arg);
			//unlock_reload_pending(cpu);
			ret = 0;
			break;

		case KVM_EXIT_KAFL_NESTED_HPRINTF:
			handle_hypercall_kafl_nested_hprintf(run, cpu, arg);
			ret = 0;
			break;

		case KVM_EXIT_KAFL_PAGE_DUMP_BP:
			handle_hypercall_kafl_page_dump_bp(run, cpu, arg, run->debug.arch.pc);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_MTF:
			handle_hypercall_kafl_mtf(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_RANGE_SUBMIT:
			handle_hypercall_kafl_range_submit(run, cpu, arg);
			ret = 0;
			break;
		case HYPERCALL_KAFL_REQ_STREAM_DATA:
			handle_hypercall_kafl_req_stream_data(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_NESTED_EARLY_RELEASE:
			handle_hypercall_kafl_nested_early_release(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_PANIC_EXTENDED:
			handle_hypercall_kafl_panic_extended(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_CREATE_TMP_SNAPSHOT:
			handle_hypercall_kafl_create_tmp_snapshot(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_DEBUG_TMP_SNAPSHOT:
			handle_hypercall_kafl_debug_tmp_snapshot(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_GET_HOST_CONFIG:
			handle_hypercall_kafl_get_host_config(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_SET_AGENT_CONFIG:
			handle_hypercall_kafl_set_agent_config(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_DUMP_FILE:
			handle_hypercall_kafl_dump_file(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_REQ_STREAM_DATA_BULK:
			handle_hypercall_kafl_req_stream_data_bulk(run, cpu, arg);
			ret = 0;
			break;
		case KVM_EXIT_KAFL_PERSIST_PAGE_PAST_SNAPSHOT:
			handle_hypercall_kafl_persist_page_past_snapshot(run, cpu, arg);
			ret = 0;
			break;
	}
	return ret;
}

