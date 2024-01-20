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

#include "exec/memory.h"
#include "qemu/main-loop.h"
#include "qemu-common.h"
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "sysemu/cpus.h"
#include "sysemu/hw_accel.h"
#include "sysemu/kvm.h"
#include "sysemu/kvm_int.h"
#include "sysemu/runstate.h"


#include "sysemu/runstate.h"
#include "nyx/debug.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/fast_vm_reload_sync.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/configuration.h"
#include "nyx/hypercall/debug.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/interface.h"
#include "nyx/kvm_nested.h"
#include "nyx/memory_access.h"
#include "nyx/nested_hypercalls.h"
#include "nyx/pt.h"
#include "nyx/redqueen.h"
#include "nyx/state/state.h"
#include "nyx/synchronization.h"

bool hypercall_enabled = false;
static bool init_state = true;

void skip_init(void)
{
    init_state = false;
}

bool pt_hypercalls_enabled(void)
{
    return hypercall_enabled;
}

void pt_setup_enable_hypercalls(void)
{
    hypercall_enabled = true;
}

void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end)
{
    nyx_trace();
    if (filter_id < INTEL_PT_MAX_RANGES) {
        GET_GLOBAL_STATE()->pt_ip_filter_configured[filter_id] = true;
        GET_GLOBAL_STATE()->pt_ip_filter_a[filter_id]          = start;
        GET_GLOBAL_STATE()->pt_ip_filter_b[filter_id]          = end;
    }
}

void hypercall_commit_filter(void)
{
}

bool setup_snapshot_once = false;


bool handle_hypercall_kafl_next_payload(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg)
{
    nyx_trace();

    if (hypercall_enabled) {
        if (init_state) {
            set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 2);
            synchronization_lock();

        } else {
            if (GET_GLOBAL_STATE()->set_agent_config_done == false) {
                nyx_abort("KVM_EXIT_KAFL_SET_AGENT_CONFIG was not called.");
                return false;
            }

            if (!setup_snapshot_once) {
                coverage_bitmap_reset();
                request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                       REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP);
                setup_snapshot_once = true;

                /* At this point we need to check if PT mode is enabled
                 * and configured. Otherwise, libxdc_init() will fail.
                 */
                if(GET_GLOBAL_STATE()->nyx_pt && GET_GLOBAL_STATE()->cap_compile_time_tracing == false) {
                    for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
                        if (GET_GLOBAL_STATE()->pt_ip_filter_configured[i]) {
                            pt_enable_ip_filtering(cpu, i, true, false);
                        }
                    }
                    pt_init_decoder(cpu);
                }
                request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                       REQUEST_LOAD_SNAPSHOT_ROOT);

                GET_GLOBAL_STATE()->in_fuzzing_mode = true;
                set_state_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                  3);
            } else {
                synchronization_lock();
                reset_timeout_detector(&GET_GLOBAL_STATE()->timeout_detector);
                GET_GLOBAL_STATE()->in_fuzzing_mode = true;

                return true;
            }
        }
    }
    return false;
}

bool acquire_print_once_bool = true;
bool release_print_once_bool = true;

static void acquire_print_once(CPUState *cpu)
{
    if (acquire_print_once_bool) {
        acquire_print_once_bool = false;
        kvm_arch_get_registers(cpu);
        nyx_debug("handle_hypercall_kafl_acquire at IP: %lx\n", get_rip(cpu));
    }
}

void handle_hypercall_kafl_acquire(struct kvm_run *run,
                                   CPUState       *cpu,
                                   uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        if (!init_state) {
            acquire_print_once(cpu);
            synchronization_enter_fuzzing_loop(cpu);
        }
    }
}

static void handle_hypercall_get_payload(struct kvm_run *run,
                                         CPUState       *cpu,
                                         uint64_t        hypercall_arg)
{
    nyx_trace();

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_GET_PAYLOAD")) {
        return;
    }

    if (GET_GLOBAL_STATE()->get_host_config_done == false) {
        nyx_abort("KVM_EXIT_KAFL_GET_HOST_CONFIG was not called...");
        return;
    }

    if (hypercall_enabled && !setup_snapshot_once) {
        nyx_debug_p(CORE_PREFIX, "Payload Address: 0x%lx\n", hypercall_arg);
        kvm_arch_get_registers(cpu);
        CPUX86State *env               = &(X86_CPU(cpu))->env;
        GET_GLOBAL_STATE()->parent_cr3 = env->cr[3] & 0xFFFFFFFFFFFFF000ULL;
        nyx_debug_p(CORE_PREFIX, "Payload CR3: 0x%lx\n",
                    (uint64_t)GET_GLOBAL_STATE()->parent_cr3);
        // print_48_pagetables(GET_GLOBAL_STATE()->parent_cr3);

        if (hypercall_arg & 0xFFF) {
            nyx_abort("Payload buffer at 0x%lx is not page-aligned!", hypercall_arg);
        }

        remap_payload_buffer(hypercall_arg, cpu);
        set_payload_buffer(hypercall_arg);
    }
}

static void set_return_value(CPUState *cpu, uint64_t return_value)
{
    kvm_arch_get_registers(cpu);
    CPUX86State *env = &(X86_CPU(cpu))->env;
    env->regs[R_EAX] = return_value;
    kvm_arch_put_registers(cpu, KVM_PUT_RUNTIME_STATE);
}

static void handle_hypercall_kafl_req_stream_data(struct kvm_run *run,
                                                  CPUState       *cpu,
                                                  uint64_t        hypercall_arg)
{
    static uint8_t req_stream_buffer[0x1000];
    if (is_called_in_fuzzing_mode("HYPERCALL_KAFL_REQ_STREAM_DATA")) {
        return;
    }

    kvm_arch_get_registers(cpu);
    /* address has to be page aligned */
    if ((hypercall_arg & 0xFFF) != 0) {
        nyx_error("REQ_STREAM_DATA: Provided address is not page aligned!\n");
        set_return_value(cpu, 0xFFFFFFFFFFFFFFFFULL);
    } else {
        read_virtual_memory(hypercall_arg, (uint8_t *)req_stream_buffer, 0x100, cpu);
        uint64_t bytes = sharedir_request_file(GET_GLOBAL_STATE()->sharedir,
                                               (const char *)req_stream_buffer,
                                               req_stream_buffer);
        if (bytes != 0xFFFFFFFFFFFFFFFFULL) {
            write_virtual_memory(hypercall_arg, (uint8_t *)req_stream_buffer, bytes,
                                 cpu);
        }
        set_return_value(cpu, bytes);
    }
}

static void handle_hypercall_kafl_req_stream_data_bulk(struct kvm_run *run,
                                                       CPUState       *cpu,
                                                       uint64_t        hypercall_arg)
{
    static uint8_t req_stream_buffer[0x1000];
    req_data_bulk_t req_data_bulk_data;

    if (is_called_in_fuzzing_mode("HYPERCALL_KAFL_REQ_STREAM_DATA_BULK")) {
        return;
    }

    kvm_arch_get_registers(cpu);
    /* address has to be page aligned */
    if ((hypercall_arg & 0xFFF) != 0) {
        nyx_error("REQ_STREAM_DATA_BULK: Provided address is not page aligned!\n");
        set_return_value(cpu, 0xFFFFFFFFFFFFFFFFUL);
        return;
    }

    uint64_t bytes = 0;
    read_virtual_memory(hypercall_arg, (uint8_t *)&req_data_bulk_data, 0x1000, cpu);

    assert(req_data_bulk_data.num_addresses <= 479);
    for (int i = 0; i < req_data_bulk_data.num_addresses; i++) {
        uint64_t ret_val =
            sharedir_request_file(GET_GLOBAL_STATE()->sharedir,
                                  (const char *)req_data_bulk_data.file_name,
                                  req_stream_buffer);
        if (ret_val == 0xFFFFFFFFFFFFFFFFUL) {
            bytes = ret_val;
            break;
        }
        if (ret_val == 0) {
            break;
        }
        bytes += ret_val;
        write_virtual_memory((uint64_t)req_data_bulk_data.addresses[i],
                             (uint8_t *)req_stream_buffer, ret_val, cpu);
    }
    set_return_value(cpu, bytes);
}

static void handle_hypercall_kafl_range_submit(struct kvm_run *run,
                                               CPUState       *cpu,
                                               uint64_t        hypercall_arg)
{
    uint64_t buffer[3];

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_RANGE_SUBMIT")) {
        return;
    }

    read_virtual_memory(hypercall_arg, (uint8_t *)&buffer, sizeof(buffer), cpu);

    if (buffer[2] >= 2) {
        nyx_warn("ignoring invalid range register %ld\n", buffer[2]);
        return;
    }

    if (GET_GLOBAL_STATE()->pt_ip_filter_configured[buffer[2]]) {
        nyx_warn("ignoring already configured range reg %ld\n", buffer[2]);
        return;
    }

    if (buffer[0] != 0 && buffer[1] != 0) {
        GET_GLOBAL_STATE()->pt_ip_filter_a[buffer[2]]          = buffer[0];
        GET_GLOBAL_STATE()->pt_ip_filter_b[buffer[2]]          = buffer[1];
        GET_GLOBAL_STATE()->pt_ip_filter_configured[buffer[2]] = true;
        nyx_debug_p(CORE_PREFIX, "Configured range register IP%ld: 0x%08lx-0x%08lx\n",
                    buffer[2], buffer[0], buffer[1]);
    } else {
        nyx_warn("ignoring invalid range register %ld (NULL page)\n", buffer[2]);
    }
}

static void release_print_once(CPUState *cpu)
{
    if (release_print_once_bool) {
        release_print_once_bool = false;
        kvm_arch_get_registers(cpu);
        nyx_debug("handle_hypercall_kafl_release at IP: %lx\n", get_rip(cpu));
    }
}

void handle_hypercall_kafl_release(struct kvm_run *run,
                                   CPUState       *cpu,
                                   uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        if (init_state) {
            nyx_debug_p(CORE_PREFIX, "[RELEASE] init_state=false\n");
            init_state = false;
        } else {
            if (hypercall_arg > 0) {
                GET_GLOBAL_STATE()->starved = 1;
            } else {
                GET_GLOBAL_STATE()->starved = 0;
            }

            synchronization_disable_pt(cpu);
            release_print_once(cpu);
        }
    }
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int                    err;
};

void handle_hypercall_kafl_mtf(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg)
{
    // assert(false);
    kvm_arch_get_registers_fast(cpu);

    nyx_printf("%s --> %lx\n", __func__, get_rip(cpu));

    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_MTF);

    kvm_remove_all_breakpoints(cpu);
    kvm_insert_breakpoint(cpu, GET_GLOBAL_STATE()->dump_page_addr, 1, 1);
    kvm_update_guest_debug(cpu, 0);

    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3,
                   GET_GLOBAL_STATE()->pt_c3_filter);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

void handle_hypercall_kafl_page_dump_bp(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg,
                                        uint64_t        page)
{
    // nyx_trace();
    kvm_arch_get_registers_fast(cpu);
    nyx_debug("%s --> %lx\n", __func__, get_rip(cpu));
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_MTF);

    bool success = false;
    // nyx_printf("page_cache_fetch = %lx\n",
    // page_cache_fetch(GET_GLOBAL_STATE()->page_cache, page, &success, false));
    page_cache_fetch(GET_GLOBAL_STATE()->page_cache, page, &success, false);
    if (success) {
        nyx_debug("%s: SUCCESS: %d\n", __func__, success);
        kvm_remove_all_breakpoints(cpu);
        kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);

    } else {
        nyx_debug("%s: FAIL: %d\n", __func__, success);

        kvm_remove_all_breakpoints(cpu);
        kvm_vcpu_ioctl(cpu, KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
        kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_MTF);
    }
}

static inline void set_page_dump_bp(CPUState *cpu, uint64_t cr3, uint64_t addr)
{
    nyx_debug("%s --> %lx %lx\n", __func__, cr3, addr);
    kvm_remove_all_breakpoints(cpu);
    kvm_insert_breakpoint(cpu, addr, 1, 1);
    kvm_update_guest_debug(cpu, 0);

    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_SET_PAGE_DUMP_CR3, cr3);
    kvm_vcpu_ioctl(cpu, KVM_VMX_PT_ENABLE_PAGE_DUMP_CR3);
}

static void handle_hypercall_kafl_cr3(struct kvm_run *run,
                                      CPUState       *cpu,
                                      uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        nyx_debug_p(CORE_PREFIX, "Setting CR3 filter: %lx\n", hypercall_arg);
        pt_set_cr3(cpu, hypercall_arg & 0xFFFFFFFFFFFFF000ULL, false);
        if (GET_GLOBAL_STATE()->dump_page) {
            set_page_dump_bp(cpu, hypercall_arg & 0xFFFFFFFFFFFFF000ULL,
                             GET_GLOBAL_STATE()->dump_page_addr);
        }
    }
}

static void handle_hypercall_kafl_submit_panic(struct kvm_run *run,
                                               CPUState       *cpu,
                                               uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_SUBMIT_PANIC")) {
        return;
    }

    if (hypercall_enabled) {
        nyx_debug_p(CORE_PREFIX, "Panic address: %lx\n", hypercall_arg);

        switch (get_current_mem_mode(cpu)) {
        case mm_32_protected:
        case mm_32_paging:
        case mm_32_pae:
            write_virtual_memory(hypercall_arg, (uint8_t *)PANIC_PAYLOAD_32,
                                 PAYLOAD_BUFFER_SIZE_32, cpu);
            break;
        case mm_64_l4_paging:
        case mm_64_l5_paging:
            write_virtual_memory(hypercall_arg, (uint8_t *)PANIC_PAYLOAD_64,
                                 PAYLOAD_BUFFER_SIZE_64, cpu);
            break;
        default:
            abort();
            break;
        }
    }
}

static void handle_hypercall_kafl_submit_kasan(struct kvm_run *run,
                                               CPUState       *cpu,
                                               uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        nyx_debug_p(CORE_PREFIX, "kASAN address:\t%lx\n", hypercall_arg);

        switch (get_current_mem_mode(cpu)) {
        case mm_32_protected:
        case mm_32_paging:
        case mm_32_pae:
            write_virtual_memory(hypercall_arg, (uint8_t *)KASAN_PAYLOAD_32,
                                 PAYLOAD_BUFFER_SIZE_32, cpu);
            break;
        case mm_64_l4_paging:
        case mm_64_l5_paging:
            write_virtual_memory(hypercall_arg, (uint8_t *)KASAN_PAYLOAD_64,
                                 PAYLOAD_BUFFER_SIZE_64, cpu);
            break;
        default:
            abort();
            break;
        }
    }
}

void handle_hypercall_kafl_panic(struct kvm_run *run,
                                 CPUState       *cpu,
                                 uint64_t        hypercall_arg)
{
    static char reason[1024];
    if (hypercall_enabled) {
        if (fast_reload_snapshot_exists(get_fast_reload_snapshot()) &&
            GET_GLOBAL_STATE()->in_fuzzing_mode)
        {
            // TODO: either remove or document + and apply for kasan/timeout as well
            if (hypercall_arg & 0x8000000000000000ULL) {
                reason[0] = '\x00';

                uint64_t address = hypercall_arg & 0x7FFFFFFFFFFFULL;
                uint64_t signal  = (hypercall_arg & 0x7800000000000ULL) >> 47;

                snprintf(reason, 1024, "PANIC IN USER MODE (SIG: %d\tat 0x%lx)\n",
                         (uint8_t)signal, address);
                set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                  reason, strlen(reason));
            } else {
                switch (hypercall_arg) {
                case 0:
                    set_crash_reason_auxiliary_buffer(
                        GET_GLOBAL_STATE()->auxilary_buffer,
                        (char *)"PANIC IN KERNEL MODE!\n",
                        strlen("PANIC IN KERNEL MODE!\n"));
                    break;
                case 1:
                    set_crash_reason_auxiliary_buffer(
                        GET_GLOBAL_STATE()->auxilary_buffer,
                        (char *)"PANIC IN USER MODE!\n",
                        strlen("PANIC IN USER MODE!\n"));
                    break;
                default:
                    set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                      (char *)"???\n",
                                                      strlen("???\n"));
                    break;
                }
            }
            synchronization_lock_crash_found();
        } else {
            nyx_abort("Agent has crashed before initializing the fuzzing loop...");
        }
    }
}

static void handle_hypercall_kafl_create_tmp_snapshot(struct kvm_run *run,
                                                      CPUState       *cpu,
                                                      uint64_t        hypercall_arg)
{
    if (!fast_reload_tmp_created(get_fast_reload_snapshot())) {
        /* decode PT data */
        pt_disable(qemu_get_cpu(0), false);

        request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                               REQUEST_SAVE_SNAPSHOT_TMP);
        set_tmp_snapshot_created(GET_GLOBAL_STATE()->auxilary_buffer, 1);
        handle_hypercall_kafl_release(run, cpu, hypercall_arg);
    } else {
        // TODO: raise an error?
    }
}

static void handle_hypercall_kafl_panic_extended(struct kvm_run *run,
                                                 CPUState       *cpu,
                                                 uint64_t        hypercall_arg)
{
    uint32_t hprintf_size = misc_data_size();
    read_virtual_memory(hypercall_arg, (uint8_t *)GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size, cpu);

    if (fast_reload_snapshot_exists(get_fast_reload_snapshot()) &&
        GET_GLOBAL_STATE()->in_fuzzing_mode)
    {
        set_crash_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                          GET_GLOBAL_STATE()->hprintf_tmp_buffer, strnlen(GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size));
        synchronization_lock_crash_found();
    } else {
        nyx_abort("Agent has crashed before initializing the fuzzing loop: %s",
                  GET_GLOBAL_STATE()->hprintf_tmp_buffer);
    }
}

static void handle_hypercall_kafl_kasan(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg)
{
    if (hypercall_enabled) {
        if (fast_reload_snapshot_exists(get_fast_reload_snapshot())) {
            synchronization_lock_asan_found();
        } else {
            nyx_warn("KASAN detected during initialization stage!\n");
        }
    }
}

static void handle_hypercall_kafl_lock(struct kvm_run *run,
                                       CPUState       *cpu,
                                       uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_LOCK")) {
        return;
    }

    if (!GET_GLOBAL_STATE()->fast_reload_pre_image) {
        nyx_debug_p(CORE_PREFIX, "Skipping pre image creation (hint: set pre=on)\n");
        return;
    }

    nyx_debug_p(CORE_PREFIX, "Creating pre image snapshot <%s>\n",
                GET_GLOBAL_STATE()->fast_reload_pre_path);

    request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                           REQUEST_SAVE_SNAPSHOT_PRE);
}

static void handle_hypercall_kafl_printf(struct kvm_run *run,
                                         CPUState       *cpu,
                                         uint64_t        hypercall_arg)
{
    uint32_t hprintf_size = misc_data_size();
    read_virtual_memory(hypercall_arg, (uint8_t *)GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size, cpu);

    set_hprintf_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, GET_GLOBAL_STATE()->hprintf_tmp_buffer,
                                 strnlen(GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size));
    synchronization_lock();
}

static void handle_hypercall_kafl_user_range_advise(struct kvm_run *run,
                                                    CPUState       *cpu,
                                                    uint64_t        hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_USER_RANGE_ADVISE")) {
        return;
    }

    kAFL_ranges *buf = malloc(sizeof(kAFL_ranges));

    for (int i = 0; i < INTEL_PT_MAX_RANGES; i++) {
        buf->ip[i]      = GET_GLOBAL_STATE()->pt_ip_filter_a[i];
        buf->size[i]    = (GET_GLOBAL_STATE()->pt_ip_filter_b[i] -
                        GET_GLOBAL_STATE()->pt_ip_filter_a[i]);
        buf->enabled[i] = (uint8_t)GET_GLOBAL_STATE()->pt_ip_filter_configured[i];
    }

    write_virtual_memory(hypercall_arg, (uint8_t *)buf, sizeof(kAFL_ranges), cpu);
    free(buf);
}

static void handle_hypercall_kafl_user_submit_mode(struct kvm_run *run,
                                                   CPUState       *cpu,
                                                   uint64_t        hypercall_arg)
{
    nyx_trace();

    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_USER_SUBMIT_MODE")) {
        return;
    }

    switch (hypercall_arg) {
    case KAFL_MODE_64:
        nyx_debug_p(CORE_PREFIX, "SUBMIT_MODE set to KAFL_MODE_64\n");
        GET_GLOBAL_STATE()->disassembler_word_width = 64;
        break;
    case KAFL_MODE_32:
        nyx_debug_p(CORE_PREFIX, "SUBMIT_MODE set to KAFL_MODE_32\n");
        GET_GLOBAL_STATE()->disassembler_word_width = 32;
        break;
    case KAFL_MODE_16:
        /* not implemented in this version (due to hypertrash hacks) */
    default:
        nyx_abort("SUBMIT_MODE set to invalid value\n");
        break;
    }
}

bool handle_hypercall_kafl_hook(struct kvm_run *run,
                                CPUState       *cpu,
                                uint64_t        hypercall_arg)
{
    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;

    for (uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++) {
        if (GET_GLOBAL_STATE()->redqueen_state &&
            (env->eip >= GET_GLOBAL_STATE()->pt_ip_filter_a[i]) &&
            (env->eip <= GET_GLOBAL_STATE()->pt_ip_filter_b[i]))
        {
            handle_hook(GET_GLOBAL_STATE()->redqueen_state);
            return true;
        } else if (cpu->singlestep_enabled &&
                   (GET_GLOBAL_STATE()->redqueen_state)->singlestep_enabled)
        {
            handle_hook(GET_GLOBAL_STATE()->redqueen_state);
            return true;
        }
    }
    return false;
}

static void handle_hypercall_kafl_user_abort(struct kvm_run *run,
                                             CPUState       *cpu,
                                             uint64_t        hypercall_arg)
{
    uint32_t hprintf_size = misc_data_size();
    read_virtual_memory(hypercall_arg, (uint8_t *)GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size, cpu);
    set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                      GET_GLOBAL_STATE()->hprintf_tmp_buffer,
                                      strnlen(GET_GLOBAL_STATE()->hprintf_tmp_buffer, hprintf_size));
    synchronization_lock();
}

void pt_enable_rqi(CPUState *cpu)
{
    GET_GLOBAL_STATE()->redqueen_enable_pending = true;
}

void pt_disable_rqi(CPUState *cpu)
{
    GET_GLOBAL_STATE()->redqueen_disable_pending      = true;
    GET_GLOBAL_STATE()->redqueen_instrumentation_mode = REDQUEEN_NO_INSTRUMENTATION;
}

void pt_set_enable_patches_pending(CPUState *cpu)
{
    GET_GLOBAL_STATE()->patches_enable_pending = true;
}

void pt_set_redqueen_instrumentation_mode(CPUState *cpu, int redqueen_mode)
{
    GET_GLOBAL_STATE()->redqueen_instrumentation_mode = redqueen_mode;
}

void pt_set_redqueen_update_blacklist(CPUState *cpu, bool newval)
{
    assert(!newval || !GET_GLOBAL_STATE()->redqueen_update_blacklist);
    GET_GLOBAL_STATE()->redqueen_update_blacklist = newval;
}

void pt_set_disable_patches_pending(CPUState *cpu)
{
    GET_GLOBAL_STATE()->patches_disable_pending = true;
}

static void handle_hypercall_kafl_dump_file(struct kvm_run *run,
                                            CPUState       *cpu,
                                            uint64_t        hypercall_arg)
{
    kafl_dump_file_t file_obj;
    char             filename[256] = { 0 };
    char            *host_path     = NULL;
    FILE            *f             = NULL;

    uint64_t vaddr = hypercall_arg;
    memset((void *)&file_obj, 0, sizeof(kafl_dump_file_t));

    if (!read_virtual_memory(vaddr, (uint8_t *)&file_obj, sizeof(kafl_dump_file_t),
                             cpu))
    {
        nyx_error("Failed to read file_obj in %s. Skipping..\n", __func__);
        goto err_out1;
    }

    if (file_obj.file_name_str_ptr != 0) {
        if (!read_virtual_memory(file_obj.file_name_str_ptr, (uint8_t *)filename,
                                 sizeof(filename) - 1, cpu))
        {
            nyx_error("Failed to read file_name_str_ptr in %s. Skipping..\n",
                      __func__);
            goto err_out1;
        }
        filename[sizeof(filename) - 1] = 0;
    }

    // nyx_error("%s: dump %lu fbytes from %s (append=%u)\n",
    //	   	__func__, file_obj.bytes, filename, file_obj.append);

    // use a tempfile if file_name_ptr == NULL or points to empty string
    if (0 == strnlen(filename, sizeof(filename))) {
        strncpy(filename, "tmp.XXXXXX", sizeof(filename) - 1);
    }

    char *base_name = basename(filename); // clobbers the filename buffer!
    assert(asprintf(&host_path, "%s/dump/%s", GET_GLOBAL_STATE()->workdir_path,
                    base_name) != -1);

    // check if base_name is mkstemp() pattern, otherwise write/append to exact name
    char *pattern = strstr(base_name, "XXXXXX");
    if (pattern) {
        unsigned suffix = strlen(pattern) - strlen("XXXXXX");
        f               = fdopen(mkstemps(host_path, suffix), "w+");
        if (file_obj.append) {
            nyx_warn("Writing unique generated file in append mode?\n");
        }
    } else {
        if (file_obj.append) {
            f = fopen(host_path, "a+");
        } else {
            f = fopen(host_path, "w+");
        }
    }

    if (!f) {
        nyx_error("%s: %s - %s\n", __func__, host_path, strerror(errno));
        goto err_out1;
    }

    uint32_t pos     = 0;
    int32_t  bytes   = file_obj.bytes;
    void    *page    = malloc(PAGE_SIZE);
    uint32_t written = 0;

    nyx_debug_p(CORE_PREFIX, "Dump %d bytes to %s (append=%u)\n", bytes, host_path,
                file_obj.append);

    while (bytes > 0) {
        if (bytes >= PAGE_SIZE) {
            read_virtual_memory(file_obj.data_ptr + pos, (uint8_t *)page, PAGE_SIZE,
                                cpu);
            written = fwrite(page, 1, PAGE_SIZE, f);
        } else {
            read_virtual_memory(file_obj.data_ptr + pos, (uint8_t *)page, bytes, cpu);
            written = fwrite(page, 1, bytes, f);
            break;
        }

        if (!written) {
            nyx_error("%s: %s - %s\n", __func__, host_path, strerror(errno));
            goto err_out2;
        }

        bytes -= written;
        pos += written;
    }


err_out2:
    free(page);
    fclose(f);
err_out1:
    free(host_path);
}

static void handle_hypercall_kafl_persist_page_past_snapshot(struct kvm_run *run,
                                                             CPUState       *cpu,
                                                             uint64_t hypercall_arg)
{
    if (is_called_in_fuzzing_mode("KVM_EXIT_KAFL_PERSIST_PAGE_PAST_SNAPSHOT")) {
        return;
    }

    CPUX86State *env = &(X86_CPU(cpu))->env;
    kvm_arch_get_registers_fast(cpu);
    hwaddr phys_addr =
        (hwaddr)get_paging_phys_addr(cpu, env->cr[3], hypercall_arg & (~0xFFF));
    assert(phys_addr != 0xffffffffffffffffULL);
    fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
}

int handle_kafl_hypercall(struct kvm_run *run,
                          CPUState       *cpu,
                          uint64_t        hypercall,
                          uint64_t        arg)
{
    int ret = -1;
    // nyx_debug("%s -> %ld\n", __func__, hypercall);

    // FIXME: ret is always 0. no default case.
    switch (hypercall) {
    case KVM_EXIT_KAFL_ACQUIRE:
        handle_hypercall_kafl_acquire(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_PAYLOAD:
        handle_hypercall_get_payload(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_PROGRAM:
        nyx_abort("Hypercall is deprecated: HYPERCALL_KAFL_GET_PROGRAM");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_GET_ARGV:
        nyx_abort("Hypercall is deprecated: HYPERCALL_KAFL_GET_ARGV");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_RELEASE:
        handle_hypercall_kafl_release(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SUBMIT_CR3:
        handle_hypercall_kafl_cr3(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SUBMIT_PANIC:
        handle_hypercall_kafl_submit_panic(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_SUBMIT_KASAN:
        handle_hypercall_kafl_submit_kasan(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PANIC:
        handle_hypercall_kafl_panic(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_KASAN:
        handle_hypercall_kafl_kasan(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_LOCK:
        handle_hypercall_kafl_lock(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_INFO:
        nyx_abort("Hypercall is deprecated: HYPERCALL_KAFL_INFO");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NEXT_PAYLOAD:
        handle_hypercall_kafl_next_payload(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PRINTF:
        handle_hypercall_kafl_printf(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PRINTK_ADDR:
        nyx_abort("Hypercall is deprecated: KVM_EXIT_KAFL_PRINTK_ADDR");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_PRINTK:
        nyx_abort("Hypercall is deprecated: KVM_EXIT_KAFL_PRINTK");
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_RANGE_ADVISE:
        handle_hypercall_kafl_user_range_advise(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_SUBMIT_MODE:
        handle_hypercall_kafl_user_submit_mode(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_FAST_ACQUIRE:
        if (handle_hypercall_kafl_next_payload(run, cpu, arg)) {
            handle_hypercall_kafl_cr3(run, cpu, arg);
            handle_hypercall_kafl_acquire(run, cpu, arg);
        }
        ret = 0;
        break;
    case KVM_EXIT_KAFL_TOPA_MAIN_FULL:
        pt_handle_overflow(cpu);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_USER_ABORT:
        handle_hypercall_kafl_user_abort(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_CONFIG:
        handle_hypercall_kafl_nested_config(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_PREPARE:
        handle_hypercall_kafl_nested_prepare(run, cpu, arg);
        ret = 0;
        break;

    case KVM_EXIT_KAFL_NESTED_ACQUIRE:
        handle_hypercall_kafl_nested_acquire(run, cpu, arg);
        ret = 0;
        break;
    case KVM_EXIT_KAFL_NESTED_RELEASE:
        handle_hypercall_kafl_nested_release(run, cpu, arg);
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
