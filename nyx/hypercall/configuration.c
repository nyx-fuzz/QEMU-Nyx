#include "qemu/osdep.h"
#include "nyx/state/state.h"
#include "nyx/hypercall/configuration.h"
#include "nyx/memory_access.h"
#include "nyx/helpers.h"

void handle_hypercall_kafl_get_host_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	uint64_t vaddr = hypercall_arg;
	host_config_t config;

	if(is_called_in_fuzzing_mode("KVM_EXIT_KAFL_GET_HOST_CONFIG")){
		return;
	}

	if (GET_GLOBAL_STATE()->get_host_config_done){
		nyx_abort((char*)"KVM_EXIT_KAFL_GET_HOST_CONFIG called twice...");
		return;
	}

	memset((void*)&config, 0, sizeof(host_config_t));

	config.host_magic = NYX_HOST_MAGIC;
	config.host_version = NYX_HOST_VERSION;
	config.bitmap_size = GET_GLOBAL_STATE()->shared_bitmap_size;
	config.ijon_bitmap_size = GET_GLOBAL_STATE()->shared_ijon_bitmap_size;
	config.payload_buffer_size = GET_GLOBAL_STATE()->shared_payload_buffer_size;
	config.worker_id = GET_GLOBAL_STATE()->worker_id;

	write_virtual_memory(vaddr, (uint8_t*)&config, sizeof(host_config_t), cpu);
	GET_GLOBAL_STATE()->get_host_config_done = true;
}

void handle_hypercall_kafl_set_agent_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg){
	uint64_t vaddr = hypercall_arg;
	agent_config_t config;

	if(is_called_in_fuzzing_mode("KVM_EXIT_KAFL_SET_AGENT_CONFIG")){
		return;
	}

	if (GET_GLOBAL_STATE()->set_agent_config_done){
		nyx_abort((char*)"KVM_EXIT_KAFL_SET_AGENT_CONFIG called twice...");
		return;
	}

	X86CPU *cpux86 = X86_CPU(cpu);
  	CPUX86State *env = &cpux86->env;

	if(read_virtual_memory(vaddr, (uint8_t*)&config, sizeof(agent_config_t), cpu)){

		if (config.agent_magic != NYX_AGENT_MAGIC){
			fprintf(stderr, "[QEMU-Nyx] Error: NYX_AGENT_MAGIC not found in agent configuration - You are probably using an outdated agent...\n");
			exit(1);
		}

		if (config.agent_version != NYX_AGENT_VERSION){
			fprintf(stderr, "[QEMU-Nyx] Error: NYX_AGENT_VERSION does not match in agent configuration (%d != %d) - You are probably using an outdated agent...\n", config.agent_version, NYX_AGENT_VERSION);
			exit(1);
		}

		GET_GLOBAL_STATE()->cap_timeout_detection = config.agent_timeout_detection;
		GET_GLOBAL_STATE()->cap_only_reload_mode = !!!config.agent_non_reload_mode; /* fix this */
		GET_GLOBAL_STATE()->cap_compile_time_tracing = config.agent_tracing;

		if(!GET_GLOBAL_STATE()->cap_compile_time_tracing && !GET_GLOBAL_STATE()->nyx_fdl){
			fprintf(stderr, "[QEMU-Nyx] Error: Attempt to fuzz target without compile-time instrumentation - Intel PT is not supported on this KVM build!\n");
			exit(1);
		}

		GET_GLOBAL_STATE()->cap_ijon_tracing = config.agent_ijon_tracing;

		if(config.agent_tracing){
			GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr = config.trace_buffer_vaddr;
            GET_GLOBAL_STATE()->pt_trace_mode = false;
		}
		if(config.agent_ijon_tracing){
			GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr = config.ijon_trace_buffer_vaddr;
		}

		GET_GLOBAL_STATE()->cap_cr3 = env->cr[3];

		GET_GLOBAL_STATE()->cap_coverage_bitmap_size = config.coverage_bitmap_size;

		GET_GLOBAL_STATE()->input_buffer_size = GET_GLOBAL_STATE()->shared_payload_buffer_size;

		if (config.input_buffer_size){
			abort();
		}

		if(apply_capabilities(cpu) == false){
			nyx_abort((char*)"applying agent configuration failed...");
		}

		if(getenv("DUMP_PAYLOAD_MODE")){
			config.dump_payloads = 1;
			write_virtual_memory(vaddr, (uint8_t*)&config, sizeof(agent_config_t), cpu);
		}

	}
	else{
		fprintf(stderr, "[QEMU-Nyx] Error: %s - failed (vaddr: 0x%lx)!\n", __func__, vaddr);
		exit(1);
	}
	GET_GLOBAL_STATE()->set_agent_config_done = true;
}
