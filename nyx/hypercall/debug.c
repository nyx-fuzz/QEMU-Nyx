#include "qemu/osdep.h"
#include <sys/time.h>
#include "nyx/synchronization.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/state/state.h"
#include "nyx/hypercall/debug.h"

//#define NYX_ENABLE_DEBUG_HYPERCALLS

#ifdef NYX_ENABLE_DEBUG_HYPERCALLS

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

void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
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
			meassure_performance();
			break;
		case 3: /* load tmp snapshot */
			if(fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_TMP);
				meassure_performance();
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
#else
void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	fprintf(stderr, "[QEMU-Nyx] Error: This hypercall (HYPERCALL_KAFL_DEBUG_TMP) is not enabled!\n");
	set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, (char*)"Disabled debug hypercall called...", strlen("Disabled debug hypercall called..."));
	synchronization_lock();
}
#endif