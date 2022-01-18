#include <stdio.h>
#include <stdint.h>
#include "kvm_nested.h"
#include "memory_access.h"
#include "debug.h"
#include "nested_hypercalls.h"
#include "interface.h"
#include "state/state.h"
#include "pt.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "qemu/main-loop.h"
#include "nyx/helpers.h"

//#define DEBUG_NESTED_HYPERCALLS


bool hypercalls_enabled = false;

bool create_snapshot = false;

uint64_t htos_cr3 = 0;
uint64_t htos_config = 0;

static bool init_state = true;

int nested_once = 0;

bool nested_setup_snapshot_once = false;



void handle_hypercall_kafl_nested_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	/* magic */
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif
	uint32_t size = 0;
	read_physical_memory(htos_config, (uint8_t*) &size, sizeof(uint32_t), cpu);
	fprintf(stderr, "--> %x\n", size);
	void* buffer = malloc(size);

	read_physical_memory(htos_config+sizeof(uint32_t), buffer, size, cpu);
	/*
	hexdump_kafl(buffer, size);

	FILE *f = fopen("/tmp/htos_configuration", "w");
	fwrite(buffer, size, 1, f);
	fclose(f);

	*/
	print_configuration(stderr, buffer, size);

	FILE* f = fopen("/tmp/hypertrash_configration", "w");
	print_configuration(f, buffer, size);
	fclose(f);

	free(buffer);
	/*
	hexdump_virtual_memory()
	_memory(0x38d31000, 0x2000, cpu);
	*/
}

#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void handle_hypercall_kafl_nested_hprintf(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
  char hprintf_buffer[0x1000];
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif
	read_physical_memory((uint64_t)run->hypercall.args[0], (uint8_t*)hprintf_buffer, 0x1000, cpu);

	//fprintf(stderr, ANSI_COLOR_YELLOW "%s" ANSI_COLOR_RESET, hprintf_buffer);

	set_hprintf_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, hprintf_buffer, strnlen(hprintf_buffer, 0x1000)+1);
	synchronization_lock_hprintf();
	//hexdump_kafl(hprintf_buffer, 0x200);
}

void handle_hypercall_kafl_nested_prepare(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//cpu->fast_reload_snapshot = (void*)fast_reload_new();
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif
	kvm_arch_get_registers(cpu);

	if((uint64_t)run->hypercall.args[0]){
		QEMU_PT_PRINTF(CORE_PREFIX, "handle_hypercall_kafl_nested_prepare:\t NUM:\t%lx\t ADDRESS:\t%lx\t CR3:\t%lx", (uint64_t)run->hypercall.args[0], (uint64_t)run->hypercall.args[1], (uint64_t)run->hypercall.args[2]);
	}
	else{
		abort();
	}
	size_t buffer_size = (size_t)((uint64_t)run->hypercall.args[0] * sizeof(uint64_t));
	uint64_t* buffer = malloc(buffer_size);
	memset(buffer, 0x0, buffer_size);

	read_physical_memory((uint64_t)run->hypercall.args[1], (uint8_t*)buffer, buffer_size, cpu);
	htos_cr3 = (uint64_t)run->hypercall.args[0];

	for(uint64_t i = 0; i < (uint64_t)run->hypercall.args[0]; i++){
		if(i == 0){
			htos_config = buffer[i];
		}
		QEMU_PT_PRINTF(CORE_PREFIX, "ADDRESS: %lx", buffer[i]);
		remap_payload_slot(buffer[i], i, cpu);
	}

	set_payload_pages(buffer, (uint32_t)run->hypercall.args[0]);

	// wipe memory 
	memset(buffer, 0x00, buffer_size);
	write_physical_memory((uint64_t)run->hypercall.args[1], (uint8_t*)buffer, buffer_size, cpu);

	free(buffer);
}

bool acquired = false;

void handle_hypercall_kafl_nested_early_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	if(!hypercalls_enabled){
		return;
	}
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif
	bool state = GET_GLOBAL_STATE()->in_reload_mode;
	if(!state){
		GET_GLOBAL_STATE()->in_reload_mode = true;
		synchronization_disable_pt(cpu);
		GET_GLOBAL_STATE()->in_reload_mode = false;
	}
	else{
		synchronization_disable_pt(cpu);
	}
}

void handle_hypercall_kafl_nested_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	hypercalls_enabled = true;
	static int rcount = 0;
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif

	if((rcount%100) == 0){

			kvm_arch_get_registers(cpu);
			//printf("TRY %s %lx %lx %lx (%d)\n", __func__, get_rip(cpu), get_nested_guest_rip(cpu), get_nested_host_rip(cpu), rcount);

	//		sleep(rand()%4);
	}
	rcount++;
		synchronization_disable_pt(cpu);
		/*
		//vm_stop(RUN_STATE_RESTORE_VM);
		qemu_mutex_lock_iothread();
		//load_snapshot("kafl", NULL);
		//vm_start();
		fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();
*/
		//kvm_vm_ioctl(kvm_state, KVM_SET_CLOCK, &data);

		//	printf("DONE %s\n", __func__);

		/*
		kvm_arch_get_registers(cpu);
		fprintf(stderr, "RELOADING DUDE %d!\n", rcount);
		qemu_mutex_lock_iothread();
		fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();
		*/
	//}
	//sleep(1);


	
	return;
	//assert(false);
	QEMU_PT_PRINTF_DEBUG("%s %d", __func__, init_state);
	//sleep(10);

	/* magic */

	//X86CPU *x86_cpu = X86_CPU(cpu);
	//CPUX86State *env = &x86_cpu->env;


	if (init_state){
		printf("INIT STATE\n");
		init_state = false;	

		//synchronization_disable_pt(cpu);

		QEMU_PT_PRINTF_DEBUG("Protocol - SEND: KAFL_PROTO_RELEASE");

	} else {
		


		//if(reload_mode || reload_mode_temp){

		//}

		//synchronization_disable_pt(cpu);


		QEMU_PT_PRINTF_DEBUG("%s UNLOCKED", __func__);

		//		printf("INTEL PT is disabled!\n");

	}


		qemu_mutex_lock_iothread();
		//fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();

		QEMU_PT_PRINTF_DEBUG("%s UNLOCKED 2", __func__);


		//kvm_cpu_synchronize_state(cpu);

	acquired = false;

}

static inline void set_page_dump_bp_nested(CPUState *cpu, uint64_t cr3, uint64_t addr){
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif
	kvm_remove_all_breakpoints(cpu);
	kvm_insert_breakpoint(cpu, addr, 1, 1);
	kvm_update_guest_debug(cpu, 0);

	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3, cr3);
	kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

void handle_hypercall_kafl_nested_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
#ifdef DEBUG_NESTED_HYPERCALLS
	printf("============> %s\n", __func__);
#endif
	if (!acquired){
		printf("TRY %s\n", __func__);

		
			printf("DONE %s\n", __func__);

		acquired = true;

		//create_fast_snapshot(cpu, true);
		request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_ROOT_NESTED_FIX_RIP);

		for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
			if(GET_GLOBAL_STATE()->pt_ip_filter_configured[i]){
				pt_enable_ip_filtering(cpu, i, true, false);
			}
		}
		pt_init_decoder(cpu);

		
		qemu_mutex_lock_iothread();
		fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();

		kvm_arch_get_registers(cpu);

		X86CPU *x86_cpu = X86_CPU(cpu);
	  CPUX86State *env = &x86_cpu->env;
				
		printf("IN FUZZING LOOP! %lx\n", env->eip);
		GET_GLOBAL_STATE()->in_fuzzing_mode = true;
		set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 3);

		/*
		if(GET_GLOBAL_STATE()->protect_payload_buffer){
			for(int i = 0; i < GET_GLOBAL_STATE()->nested_payload_pages_num; i++){
				remap_payload_slot_protected(GET_GLOBAL_STATE()->nested_payload_pages[i], i, cpu);
			}
		}
		*/

	}

	synchronization_lock();
	

			kvm_arch_get_registers(cpu);

	uint64_t cr3 = get_nested_host_cr3(cpu) & 0xFFFFFFFFFFFFF000ULL;
	//fprintf(stderr, "CR3 -> 0x%lx\n", cr3);
	pt_set_cr3(cpu, cr3, false);
	GET_GLOBAL_STATE()->parent_cr3 = cr3;

	if(GET_GLOBAL_STATE()->dump_page){
		set_page_dump_bp_nested(cpu, cr3, GET_GLOBAL_STATE()->dump_page_addr);
	}

	kvm_nested_get_info(cpu);

	synchronization_enter_fuzzing_loop(cpu);

	return;
}