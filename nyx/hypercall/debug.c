#include "qemu/osdep.h"
#include <sys/time.h>
#include "nyx/synchronization.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/state/state.h"
#include "nyx/hypercall/debug.h"
#include "nyx/memory_access.h"

//#define NYX_DEBUG

#ifdef NYX_DEBUG

typedef struct nyx_debug_s{
	uint64_t arg0;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t arg3;
} nyx_debug_t;

void handle_hypercall_kafl_debug(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	//X86CPU *x86_cpu = X86_CPU(cpu);
	//CPUX86State *env = &x86_cpu->env;

	uint64_t data = 0;
	CPUX86State *env = &(X86_CPU(cpu))->env;
	nyx_debug_t debug_req;
	assert(read_virtual_memory(hypercall_arg, (uint8_t*)&debug_req, sizeof(debug_req), cpu));
	fast_reload_t* snapshot = NULL;


	static bool first = true;

	//printf("CALLED %s: %lx\n", __func__, hypercall_arg);
	switch(debug_req.arg0){
		case 0: /* create root snapshot */
			abort();
			if(!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_ROOT_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_ROOT);
			}
			break;
		case 1: /* create tmp snapshot */
			abort();
			//printf("%s: create tmp...(RIP: %lx)\n", __func__, get_rip(cpu));
			if(!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_TMP);
			}
			break;
		case 2: /* load root snapshot (+ discard tmp snapshot) */
			abort();
			//printf("%s: load root...(RIP: %lx)\n", __func__, get_rip(cpu));
			if(fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				reload_request_discard_tmp(GET_GLOBAL_STATE()->reload_state);
			}
			request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_ROOT);
			//meassure_performance();
			break;
		case 3: /* load tmp snapshot */			
			abort();
			if(fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS)){
				request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_LOAD_SNAPSHOT_TMP);
				//meassure_performance();
			}
			break;
		case 5: // firefox debug hypercall
			abort();
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
		case 6:
			switch (debug_req.arg3) {
				case 0:
					assert(read_virtual_memory(debug_req.arg1, (uint8_t*)&data, 1, cpu));
					assert((uint8_t)data == (uint8_t)debug_req.arg2);
					break;
				case 1:
					assert(read_virtual_memory(debug_req.arg1, (uint8_t*)&data, 2, cpu));
					assert((uint16_t)data == (uint16_t)debug_req.arg2);
					break;
				case 2:
					assert(read_virtual_memory(debug_req.arg1, (uint8_t*)&data, 4, cpu));
					assert((uint32_t)data == (uint32_t)debug_req.arg2);
					break;
				case 3:
					assert(read_virtual_memory(debug_req.arg1, (uint8_t*)&data, 8, cpu));
					assert((uint64_t)data == (uint64_t)debug_req.arg2);
					break;
				default:
					abort();
			}
			break;

		case 7:
			kvm_arch_get_registers_fast(cpu);
			hwaddr phys_addr = (hwaddr) get_paging_phys_addr(cpu, env->cr[3], debug_req.arg1);
			snapshot = get_fast_reload_snapshot();
	
			assert(snapshot != NULL);

			switch (debug_req.arg3) {
				case 0:
					assert(read_snapshot_memory(snapshot, phys_addr, (uint8_t *)&data, 1));
					assert((uint8_t)data == (uint8_t)debug_req.arg2);
					break;
				case 1:
					assert(read_snapshot_memory(snapshot, phys_addr, (uint8_t *)&data, 2));
					assert((uint16_t)data == (uint16_t)debug_req.arg2);
					break;
				case 2:
					assert(read_snapshot_memory(snapshot, phys_addr, (uint8_t *)&data, 4));
					assert((uint32_t)data == (uint32_t)debug_req.arg2);
					break;
				case 3:
					assert(read_snapshot_memory(snapshot, phys_addr, (uint8_t *)&data, 8));
					assert((uint64_t)data == (uint64_t)debug_req.arg2);
					break;
				default:
					abort();
			}
			break;
			
		default:
			abort();
	}
}
#else
void handle_hypercall_kafl_debug(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	fprintf(stderr, "[QEMU-Nyx] Error: This hypercall (HYPERCALL_KAFL_DEBUG_TMP) is not enabled!\n");
	set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, (char*)"Disabled debug hypercall called...", strlen("Disabled debug hypercall called..."));
	synchronization_lock();
}
#endif