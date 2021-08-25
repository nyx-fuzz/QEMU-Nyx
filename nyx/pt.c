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
#include "target/i386/cpu.h"
#include "nyx/pt.h"
#include "exec/memory.h"
#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "sysemu/cpus.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/memory_access.h"
#include "nyx/interface.h"
#include "nyx/debug.h"
#include "nyx/file_helper.h"
#ifdef CONFIG_REDQUEEN
#include "nyx/redqueen.h"
#include "nyx/redqueen_patch.h"
#include "nyx/patcher.h"
#endif
#include "nyx/page_cache.h"
#include "nyx/state/state.h"
#include <libxdc.h>
#include "nyx/helpers.h"
#include "nyx/trace_dump.h"
#include "nyx/redqueen_trace.h"

#define PT_BUFFER_MMAP_ADDR 0x3ffff0000000

static void pt_set(CPUState *cpu, run_on_cpu_data arg){
	asm volatile("" ::: "memory");
}

static inline int pt_cmd_hmp_context(CPUState *cpu, uint64_t cmd){
	cpu->pt_ret = -1;
	if(pt_hypercalls_enabled()){
		QEMU_PT_PRINTF(PT_PREFIX, "Error: HMP commands are ignored if kafl tracing mode is enabled (-kafl)!");
	}
	else{
		cpu->pt_cmd = cmd;
		run_on_cpu(cpu, pt_set, RUN_ON_CPU_NULL);
	}
	return cpu->pt_ret;
}

static int pt_cmd(CPUState *cpu, uint64_t cmd, bool hmp_mode){
	if (hmp_mode){
		return pt_cmd_hmp_context(cpu, cmd);
	}
	else {
		cpu->pt_cmd = cmd;
		pt_pre_kvm_run(cpu);
		return cpu->pt_ret;
	}
}

static inline int pt_ioctl(int fd, unsigned long request, unsigned long arg){
	if (!fd){
		return -EINVAL;
	}
	return ioctl(fd, request, arg);
}

#ifdef DUMP_AND_DEBUG_PT
void dump_pt_trace(void* buffer, int bytes){
	static FILE* f = NULL;
	static int fcounter = 0; 
	static size_t size = 0;
	char filename[256];

	

	if(!f){
		snprintf(filename, 256, "/tmp/trace_data/data_%d", fcounter);
		f = fopen(filename, "wb");
	}

	size += fwrite(buffer, bytes , 1, f) * bytes;

	if(size >= 0x80000000){ // 2GB
		fclose(f);
		fcounter++;
		size = 0;
		snprintf(filename, 256, "/tmp/trace_data/data_%d", fcounter);
		f = fopen(filename, "wb");
	}
}
#endif

void pt_dump(CPUState *cpu, int bytes){
	//pt_write_pt_dump_file(cpu->pt_mmap, bytes);

	if(!(GET_GLOBAL_STATE()->redqueen_state && GET_GLOBAL_STATE()->redqueen_state->intercept_mode)){
		if (GET_GLOBAL_STATE()->in_fuzzing_mode && GET_GLOBAL_STATE()->decoder_page_fault == false && GET_GLOBAL_STATE()->decoder && !GET_GLOBAL_STATE()->dump_page){
			GET_GLOBAL_STATE()->pt_trace_size += bytes;
			//dump_pt_trace(cpu->pt_mmap, bytes);
			pt_write_pt_dump_file(cpu->pt_mmap, bytes);
			decoder_result_t result = libxdc_decode(GET_GLOBAL_STATE()->decoder, cpu->pt_mmap, bytes);
			switch(result){
				case decoder_success:
					break;
				case decoder_success_pt_overflow:
					cpu->intel_pt_run_trashed = true;
					break;
				case decoder_page_fault:
					//fprintf(stderr, "Page not found => 0x%lx\n", libxdc_get_page_fault_addr(GET_GLOBAL_STATE()->decoder));
					GET_GLOBAL_STATE()->decoder_page_fault = true;
					GET_GLOBAL_STATE()->decoder_page_fault_addr = libxdc_get_page_fault_addr(GET_GLOBAL_STATE()->decoder);
					break;
				case decoder_unkown_packet:
					fprintf(stderr, "WARNING: libxdc_decode returned unknown_packet\n");
					break;
				case decoder_error:
					fprintf(stderr, "WARNING: libxdc_decode returned decoder_error\n");
					break;
			}
		}
	}
}


int pt_enable(CPUState *cpu, bool hmp_mode){
	if(!fast_reload_set_bitmap(get_fast_reload_snapshot())){
		coverage_bitmap_reset();
	}
	if (GET_GLOBAL_STATE()->trace_mode) {
		redqueen_trace_reset();
		alt_bitmap_reset();
	}
	pt_truncate_pt_dump_file();
	return pt_cmd(cpu, KVM_VMX_PT_ENABLE, hmp_mode);
}
	
int pt_disable(CPUState *cpu, bool hmp_mode){
	//printf("%s\n", __func__);
	int r = pt_cmd(cpu, KVM_VMX_PT_DISABLE, hmp_mode);
	return r;
}

int pt_set_cr3(CPUState *cpu, uint64_t val, bool hmp_mode){
	if (val == GET_GLOBAL_STATE()->pt_c3_filter){
		return 0; // nothing changed  
	}
	//fprintf(stderr, "=========== %s %lx ============\n", __func__, val);
	int r = 0;
	
	if (cpu->pt_enabled){
		return -EINVAL;
	}
	if (GET_GLOBAL_STATE()->pt_c3_filter && GET_GLOBAL_STATE()->pt_c3_filter != val){
		//QEMU_PT_PRINTF(PT_PREFIX, "Reconfigure CR3-Filtering!");
		GET_GLOBAL_STATE()->pt_c3_filter = val;
		r += pt_cmd(cpu, KVM_VMX_PT_CONFIGURE_CR3, hmp_mode);
		r += pt_cmd(cpu, KVM_VMX_PT_ENABLE_CR3, hmp_mode);
		return r;
	}
	GET_GLOBAL_STATE()->pt_c3_filter = val;
	r += pt_cmd(cpu, KVM_VMX_PT_CONFIGURE_CR3, hmp_mode);
	r += pt_cmd(cpu, KVM_VMX_PT_ENABLE_CR3, hmp_mode);
	return r;
}

int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, bool redqueen, bool hmp_mode){
	int r = 0;

	if(addrn > 3){
		return -1;
	}

	if (cpu->pt_enabled){
		return -EINVAL;
	}
		
	if(GET_GLOBAL_STATE()->pt_ip_filter_a[addrn] > GET_GLOBAL_STATE()->pt_ip_filter_b[addrn]){
		QEMU_PT_PRINTF(PT_PREFIX, "Error (ip_a > ip_b) 0x%lx-0x%lx", GET_GLOBAL_STATE()->pt_ip_filter_a[addrn] , GET_GLOBAL_STATE()->pt_ip_filter_b[addrn]);
		return -EINVAL;
	}

	if(GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn]){
		pt_disable_ip_filtering(cpu, addrn, hmp_mode);
	}

	QEMU_PT_PRINTF(PT_PREFIX, "Configuring new trace region (addr%d, 0x%lx-0x%lx)", addrn, GET_GLOBAL_STATE()->pt_ip_filter_a[addrn] , GET_GLOBAL_STATE()->pt_ip_filter_b[addrn]);
	
	if(GET_GLOBAL_STATE()->pt_ip_filter_configured[addrn] && GET_GLOBAL_STATE()->pt_ip_filter_a[addrn] != 0 && GET_GLOBAL_STATE()->pt_ip_filter_b[addrn] != 0){
			r += pt_cmd(cpu, KVM_VMX_PT_CONFIGURE_ADDR0+addrn, hmp_mode);
			r += pt_cmd(cpu, KVM_VMX_PT_ENABLE_ADDR0+addrn, hmp_mode);
			GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn] = true;
	}
	return r;
}

void pt_init_decoder(CPUState *cpu){
	uint64_t filters[4][2] = {0};

	/* it's time to clean up this code -.- */
	filters[0][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[0];
	filters[0][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[0];
	filters[1][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[1];
	filters[1][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[1];
	filters[2][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[2];
	filters[2][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[2];
	filters[3][0] = GET_GLOBAL_STATE()->pt_ip_filter_a[3];
	filters[3][1] = GET_GLOBAL_STATE()->pt_ip_filter_b[3];

	assert(GET_GLOBAL_STATE()->decoder == NULL);
	assert(GET_GLOBAL_STATE()->shared_bitmap_ptr != NULL);
	assert(GET_GLOBAL_STATE()->shared_bitmap_size != 0);
	GET_GLOBAL_STATE()->decoder = libxdc_init(filters, (void* (*)(void*, uint64_t, bool*))page_cache_fetch2, GET_GLOBAL_STATE()->page_cache, GET_GLOBAL_STATE()->shared_bitmap_ptr, GET_GLOBAL_STATE()->shared_bitmap_size);

	libxdc_register_bb_callback(GET_GLOBAL_STATE()->decoder, (void (*)(void*, disassembler_mode_t, uint64_t, uint64_t))redqueen_callback, GET_GLOBAL_STATE()->redqueen_state);

	alt_bitmap_init(
			GET_GLOBAL_STATE()->shared_bitmap_ptr,
			GET_GLOBAL_STATE()->shared_bitmap_size);
}

int pt_disable_ip_filtering(CPUState *cpu, uint8_t addrn, bool hmp_mode){
	int r = 0;
	switch(addrn){
		case 0:
		case 1:
		case 2:
		case 3:
			r = pt_cmd(cpu, KVM_VMX_PT_DISABLE_ADDR0+addrn, hmp_mode);
			if(GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn]){
				GET_GLOBAL_STATE()->pt_ip_filter_enabled[addrn] = false;
			}
			break;
		default:
			r = -EINVAL;
	}
	return r;
}

void pt_kvm_init(CPUState *cpu){
	cpu->pt_cmd = 0;
	cpu->pt_enabled = false;
	cpu->pt_fd = 0;

	cpu->pt_decoder_state = NULL;
	//cpu->redqueen_state=NULL;
	//cpu->redqueen_patch_state = patcher_new(cpu);

	//init_redqueen_patch_state();

	cpu->reload_pending = false;
	cpu->intel_pt_run_trashed = false;
}

struct vmx_pt_filter_iprs {
	__u64 a;
	__u64 b;
};

pthread_mutex_t pt_dump_mutex = PTHREAD_MUTEX_INITIALIZER;

void pt_pre_kvm_run(CPUState *cpu){
	pthread_mutex_lock(&pt_dump_mutex);
	int ret;
	struct vmx_pt_filter_iprs filter_iprs;

	if(GET_GLOBAL_STATE()->patches_disable_pending){
		//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "patches disable");
		assert(false); /* remove this branch */
		GET_GLOBAL_STATE()->patches_disable_pending = false;
	}

	if(GET_GLOBAL_STATE()->patches_enable_pending){
		//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "patches enable");
		assert(false); /* remove this branch */
		GET_GLOBAL_STATE()->patches_enable_pending = false;
	}


	//if(cpu->redqueen_enable_pending){
	if(GET_GLOBAL_STATE()->redqueen_enable_pending){
		//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "rq enable");
		if (GET_GLOBAL_STATE()->redqueen_state){
			enable_rq_intercept_mode(GET_GLOBAL_STATE()->redqueen_state);
		}
		//cpu->redqueen_enable_pending = false;
		GET_GLOBAL_STATE()->redqueen_enable_pending = false;
		//qemu_cpu_kick_self();
	}

	//if(cpu->redqueen_disable_pending){
	if(GET_GLOBAL_STATE()->redqueen_disable_pending){
		//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "rq disable");
		if (GET_GLOBAL_STATE()->redqueen_state){
			disable_rq_intercept_mode(GET_GLOBAL_STATE()->redqueen_state);
		}
		//cpu->redqueen_disable_pending = false;
		GET_GLOBAL_STATE()->redqueen_disable_pending = false;
		//qemu_cpu_kick_self();
	}
	if(GET_GLOBAL_STATE()->pt_trace_mode || GET_GLOBAL_STATE()->pt_trace_mode_force){		
		if (!cpu->pt_fd) {
			cpu->pt_fd = kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SETUP_FD, (unsigned long)0);
			assert(cpu->pt_fd != -1);
			ret = ioctl(cpu->pt_fd, KVM_VMX_PT_GET_TOPA_SIZE, (unsigned long)0x0);
			
			cpu->pt_mmap = mmap((void*)PT_BUFFER_MMAP_ADDR, ret, PROT_READ|PROT_WRITE, MAP_SHARED, cpu->pt_fd, 0);
			assert(cpu->pt_mmap != (void*)0xFFFFFFFFFFFFFFFF);
			assert(mmap(cpu->pt_mmap+ret, 0x1000, PROT_READ|PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0) == (void*)(cpu->pt_mmap+ret)); //;!= (void*)0xFFFFFFFFFFFFFFFF); // add an extra page to have enough space for an additional PT_TRACE_END byte  
					
			debug_printf("\t\t============> pt_mmap:%p - %p\n", cpu->pt_mmap, cpu->pt_mmap+ret);

			memset(cpu->pt_mmap+ret, 0x55, 0x1000);
		}
		
		if (cpu->pt_cmd){
			switch(cpu->pt_cmd){
				case KVM_VMX_PT_ENABLE:
					//fprintf(stderr, "=========== KVM_VMX_PT_ENABLE ============\n");

					if (cpu->pt_fd){
						/* dump for the very last time before enabling VMX_PT ... just in case */
						ioctl(cpu->pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, (unsigned long)0);

						if (!ioctl(cpu->pt_fd, cpu->pt_cmd, 0)){
							cpu->pt_enabled = true;
						}
					}
					break;
				case KVM_VMX_PT_DISABLE:
					//fprintf(stderr, "=========== KVM_VMX_PT_DISABLE ============\n");

					if (cpu->pt_fd){
						ret = ioctl(cpu->pt_fd, cpu->pt_cmd, 0);
						if (ret > 0){
							//QEMU_PT_PRINTF(PT_PREFIX, "KVM_VMX_PT_DISABLE %d", ret);
							pt_dump(cpu, ret);
							cpu->pt_enabled = false;
						}
					}
					break;
				
				/* ip filtering configuration */	
				case KVM_VMX_PT_CONFIGURE_ADDR0:
				case KVM_VMX_PT_CONFIGURE_ADDR1:
				case KVM_VMX_PT_CONFIGURE_ADDR2:
				case KVM_VMX_PT_CONFIGURE_ADDR3:
					filter_iprs.a = GET_GLOBAL_STATE()->pt_ip_filter_a[(cpu->pt_cmd)-KVM_VMX_PT_CONFIGURE_ADDR0];
					filter_iprs.b = GET_GLOBAL_STATE()->pt_ip_filter_b[(cpu->pt_cmd)-KVM_VMX_PT_CONFIGURE_ADDR0];
					ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, (unsigned long)&filter_iprs);
					break;
				case KVM_VMX_PT_ENABLE_ADDR0:
				case KVM_VMX_PT_ENABLE_ADDR1:
				case KVM_VMX_PT_ENABLE_ADDR2:
				case KVM_VMX_PT_ENABLE_ADDR3:
					ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, (unsigned long)0);
					break;
				case KVM_VMX_PT_CONFIGURE_CR3:
					//fprintf(stderr, "=========== KVM_VMX_PT_CONFIGURE_CR3 ============\n");

					ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, GET_GLOBAL_STATE()->pt_c3_filter);
					break;
				case KVM_VMX_PT_ENABLE_CR3:
					//fprintf(stderr, "=========== KVM_VMX_PT_ENABLE_CR3 ============\n");

					ret = pt_ioctl(cpu->pt_fd, cpu->pt_cmd, (unsigned long)0);
					break;
				default:
					if (cpu->pt_fd){
						ioctl(cpu->pt_fd, cpu->pt_cmd, 0);  
					}
					break;
				}
			cpu->pt_cmd = 0;
			cpu->pt_ret = 0;
			//kvm_cpu_synchronize_state(cpu);
		}
	}
	pthread_mutex_unlock(&pt_dump_mutex);
}

void pt_handle_overflow(CPUState *cpu){
	pthread_mutex_lock(&pt_dump_mutex);
	int overflow = ioctl(cpu->pt_fd, KVM_VMX_PT_CHECK_TOPA_OVERFLOW, (unsigned long)0);
	if (overflow > 0){
		//cpu->overflow_counter++;
		pt_dump(cpu, overflow);
	}  
	
	/*else{
		printf("CPU NOT ENABLED?!\n");
		assert(false);
	}
	*/
	pthread_mutex_unlock(&pt_dump_mutex);
}

void pt_post_kvm_run(CPUState *cpu){
	if(GET_GLOBAL_STATE()->pt_trace_mode || GET_GLOBAL_STATE()->pt_trace_mode_force){

		//printf("%s\n", __func__);
		//int overflow;
		//if (cpu->pt_enabled){
		pt_handle_overflow(cpu);
		//unlock_reload_pending(cpu);
		//}
	}
}
