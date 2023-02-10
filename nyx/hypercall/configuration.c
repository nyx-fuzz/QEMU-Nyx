#include "qemu/osdep.h"

#include "nyx/debug.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/configuration.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include "nyx/debug.h"

void handle_hypercall_kafl_get_host_config(struct kvm_run *run,
                                           CPUState       *cpu,
                                           uint64_t        hypercall_arg)
{
    uint64_t      vaddr = hypercall_arg;
    host_config_t config;

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_GET_HOST_CONFIG")) {
        return;
    }

    if (GET_GLOBAL_STATE()->get_host_config_done) {
        nyx_debug("KVM_EXIT_KAFL_GET_HOST_CONFIG called again...");
    }

    memset((void *)&config, 0, sizeof(host_config_t));

    config.host_magic          = NYX_HOST_MAGIC;
    config.host_version        = NYX_HOST_VERSION;
    config.bitmap_size         = GET_GLOBAL_STATE()->shared_bitmap_size;
    config.ijon_bitmap_size    = GET_GLOBAL_STATE()->shared_ijon_bitmap_size;
    config.payload_buffer_size = GET_GLOBAL_STATE()->shared_payload_buffer_size;
    config.worker_id           = GET_GLOBAL_STATE()->worker_id;

    write_virtual_memory(vaddr, (uint8_t *)&config, sizeof(host_config_t), cpu);
    GET_GLOBAL_STATE()->get_host_config_done = true;
}

void handle_hypercall_kafl_set_agent_config(struct kvm_run *run,
                                            CPUState       *cpu,
                                            uint64_t        hypercall_arg)
{
    uint64_t       vaddr = hypercall_arg;
    agent_config_t config;

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_SET_AGENT_CONFIG")) {
        return;
    }

    if (GET_GLOBAL_STATE()->set_agent_config_done) {
        nyx_abort("KVM_EXIT_KAFL_SET_AGENT_CONFIG called twice...");
    }

    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;

    if (read_virtual_memory(vaddr, (uint8_t *)&config, sizeof(agent_config_t), cpu)) {
        if (config.agent_magic != NYX_AGENT_MAGIC) {
            nyx_abort("NYX_AGENT_MAGIC mismatch - agent outdated? (%x != %x)\n",
                      config.agent_magic, NYX_AGENT_MAGIC);
        }

        if (config.agent_version != NYX_AGENT_VERSION) {
            nyx_abort("NYX_AGENT_VERSION mismatch - agent outdated? (%x != %x)\n",
                      config.agent_version, NYX_AGENT_VERSION);
        }

        GET_GLOBAL_STATE()->cap_timeout_detection = config.agent_timeout_detection;
        GET_GLOBAL_STATE()->cap_only_reload_mode =
            !!!config.agent_non_reload_mode; /* fix this */
        GET_GLOBAL_STATE()->cap_compile_time_tracing = config.agent_tracing;

        if (!GET_GLOBAL_STATE()->cap_compile_time_tracing &&
            !GET_GLOBAL_STATE()->nyx_pt)
        {
            nyx_abort("No Intel PT support on this KVM build and no "
                      "compile-time instrumentation enabled in the target\n");
        }

        GET_GLOBAL_STATE()->cap_ijon_tracing = config.agent_ijon_tracing;

        if (config.agent_tracing) {
            GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr =
                config.trace_buffer_vaddr;
            GET_GLOBAL_STATE()->pt_trace_mode = false;
        }
        if (config.agent_ijon_tracing) {
            GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr =
                config.ijon_trace_buffer_vaddr;
        }

        GET_GLOBAL_STATE()->cap_cr3                  = env->cr[3];
        GET_GLOBAL_STATE()->cap_coverage_bitmap_size = config.coverage_bitmap_size;
        GET_GLOBAL_STATE()->input_buffer_size =
            GET_GLOBAL_STATE()->shared_payload_buffer_size;

        if (config.input_buffer_size) {
            abort();
        }

        if (apply_capabilities(cpu) == false) {
            nyx_abort("Applying agent configuration failed...");
        }

        if (getenv("DUMP_PAYLOAD_MODE")) {
            config.dump_payloads = 1;
            write_virtual_memory(vaddr, (uint8_t *)&config, sizeof(agent_config_t),
                                 cpu);
        }

    } else {
        nyx_abort("%s - failed (vaddr: 0x%lx)!\n", __func__, vaddr);
    }
    GET_GLOBAL_STATE()->set_agent_config_done = true;
}
