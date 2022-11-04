#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "nested_hypercalls.h"
#include "debug.h"
#include "interface.h"
#include "kvm_nested.h"
#include "memory_access.h"
#include "nyx/helpers.h"
#include "pt.h"
#include "state/state.h"
#include <stdint.h>
#include <stdio.h>

// #define DEBUG_NESTED_HYPERCALLS


bool hypercalls_enabled = false;
bool create_snapshot    = false;

uint64_t htos_cr3    = 0;
uint64_t htos_config = 0;

int nested_once = 0;

bool nested_setup_snapshot_once = false;


void handle_hypercall_kafl_nested_config(struct kvm_run *run,
                                         CPUState       *cpu,
                                         uint64_t        hypercall_arg)
{
    /* magic */
    nyx_trace();
    uint32_t size = 0;
    read_physical_memory(htos_config, (uint8_t *)&size, sizeof(uint32_t), cpu);

    void *buffer = malloc(size);

    read_physical_memory(htos_config + sizeof(uint32_t), buffer, size, cpu);
    print_configuration(stderr, buffer, size);

    FILE *f = fopen("/tmp/hypertrash_configration", "w");
    print_configuration(f, buffer, size);
    fclose(f);

    free(buffer);
}

void handle_hypercall_kafl_nested_hprintf(struct kvm_run *run,
                                          CPUState       *cpu,
                                          uint64_t        hypercall_arg)
{
    nyx_trace();
    char hprintf_buffer[0x1000];
    read_physical_memory((uint64_t)run->hypercall.args[0], (uint8_t *)hprintf_buffer,
                         0x1000, cpu);

    set_hprintf_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, hprintf_buffer,
                                 strnlen(hprintf_buffer, 0x1000) + 1);
    synchronization_lock_hprintf();
}

void handle_hypercall_kafl_nested_prepare(struct kvm_run *run,
                                          CPUState       *cpu,
                                          uint64_t        hypercall_arg)
{
    nyx_trace();
    kvm_arch_get_registers(cpu);

    if ((uint64_t)run->hypercall.args[0]) {
        nyx_debug_p(CORE_PREFIX,
                    "handle_hypercall_kafl_nested_prepare:\t NUM:\t%lx\t "
                    "ADDRESS:\t%lx\t CR3:\t%lx\n",
                    (uint64_t)run->hypercall.args[0], (uint64_t)run->hypercall.args[1],
                    (uint64_t)run->hypercall.args[2]);
    } else {
        abort();
    }

    size_t buffer_size = (size_t)((uint64_t)run->hypercall.args[0] * sizeof(uint64_t));
    uint64_t *buffer = malloc(buffer_size);
    memset(buffer, 0x0, buffer_size);

    read_physical_memory((uint64_t)run->hypercall.args[1], (uint8_t *)buffer,
                         buffer_size, cpu);
    htos_cr3 = (uint64_t)run->hypercall.args[0];

    for (uint64_t i = 0; i < (uint64_t)run->hypercall.args[0]; i++) {
        if (i == 0) {
            htos_config = buffer[i];
        }
        nyx_debug_p(CORE_PREFIX, "ADDRESS: %lx\n", buffer[i]);
        remap_payload_slot(buffer[i], i, cpu);
    }

    set_payload_pages(buffer, (uint32_t)run->hypercall.args[0]);

    // wipe memory
    memset(buffer, 0x00, buffer_size);
    write_physical_memory((uint64_t)run->hypercall.args[1], (uint8_t *)buffer,
                          buffer_size, cpu);

    free(buffer);
}

bool acquired = false;

void handle_hypercall_kafl_nested_early_release(struct kvm_run *run,
                                                CPUState       *cpu,
                                                uint64_t        hypercall_arg)
{
    nyx_trace();

    if (!hypercalls_enabled) {
        return;
    }

    bool state = GET_GLOBAL_STATE()->in_reload_mode;
    if (!state) {
        GET_GLOBAL_STATE()->in_reload_mode = true;
        synchronization_disable_pt(cpu);
        GET_GLOBAL_STATE()->in_reload_mode = false;
    } else {
        synchronization_disable_pt(cpu);
    }
}

void handle_hypercall_kafl_nested_release(struct kvm_run *run,
                                          CPUState       *cpu,
                                          uint64_t        hypercall_arg)
{
    nyx_trace();
    // TODO not implemented - see git history for scraps
    nyx_error("Not implemented.\n");
    abort();
}

static inline void set_page_dump_bp_nested(CPUState *cpu, uint64_t cr3, uint64_t addr)
{
    nyx_trace();

    kvm_remove_all_breakpoints(cpu);
    kvm_insert_breakpoint(cpu, addr, 1, 1);
    kvm_update_guest_debug(cpu, 0);

    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3, cr3);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

void handle_hypercall_kafl_nested_acquire(struct kvm_run *run,
                                          CPUState       *cpu,
                                          uint64_t        hypercall_arg)
{
    nyx_trace();

    if (!acquired) {
        acquired = true;

        // create_fast_snapshot(cpu, true);
        request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                               REQUEST_SAVE_SNAPSHOT_ROOT_NESTED_FIX_RIP);

        for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
            if (GET_GLOBAL_STATE()->pt_ip_filter_configured[i]) {
                pt_enable_ip_filtering(cpu, i, true, false);
            }
        }
        pt_init_decoder(cpu);


        qemu_mutex_lock_iothread();
        fast_reload_restore(get_fast_reload_snapshot());
        qemu_mutex_unlock_iothread();

        kvm_arch_get_registers(cpu);

        GET_GLOBAL_STATE()->in_fuzzing_mode = true;
        set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 3);
    }

    synchronization_lock();

    kvm_arch_get_registers(cpu);

    uint64_t cr3 = get_nested_host_cr3(cpu) & 0xFFFFFFFFFFFFF000ULL;
    pt_set_cr3(cpu, cr3, false);
    GET_GLOBAL_STATE()->parent_cr3 = cr3;

    if (GET_GLOBAL_STATE()->dump_page) {
        set_page_dump_bp_nested(cpu, cr3, GET_GLOBAL_STATE()->dump_page_addr);
    }

    kvm_nested_get_info(cpu);

    synchronization_enter_fuzzing_loop(cpu);

    return;
}