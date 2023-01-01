#include "qemu/osdep.h"

#include "sysemu/kvm.h"
#include <sys/time.h>
#include "qapi/error.h"

#include "nyx/fast_vm_reload.h"
#include "nyx/hypercall/debug.h"
#include "nyx/mem_split.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include "nyx/synchronization.h"
#include "qapi/qapi-commands-dump.h"
#include "exec/ram_addr.h"

#ifdef NYX_DEBUG
#define NYX_ENABLE_DEBUG_HYPERCALLS
#endif 

#ifdef NYX_ENABLE_DEBUG_HYPERCALLS

static double get_time(void)
{
    struct timeval  t;
    struct timezone tzp;
    gettimeofday(&t, &tzp);
    return t.tv_sec + t.tv_usec * 1e-6;
}

static void print_time_diff(int iterations)
{
    static bool   init       = true;
    static double start_time = 0.0;
    static double end_time   = 0.0;

    if (init) {
        init = false;
        printf("start time is zero!\n");
        start_time = get_time();
    } else {
        end_time            = get_time();
        double elapsed_time = end_time - start_time;
        printf("Done in %f seconds\n", elapsed_time);
        printf("Performance: %f\n", iterations / elapsed_time);
        start_time = get_time();
    }
}

static void meassure_performance(void)
{
    static int perf_counter = 0;
    if ((perf_counter % 1000) == 0) {
        print_time_diff(1000);
    }
    perf_counter++;
}

static void handle_hypercall_kafl_debug_virt_to_ram_offset(struct kvm_run *run,
                                                        CPUState       *cpu,
                                                        uint64_t        hypercall_arg)
{
    static bool once = true;
    CPUX86State *env;
    static uint64_t ram_block = 0;
    RAMBlock *block;

    if(once){
        if (!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state,
                                  REQUEST_ROOT_EXISTS))
        {
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                REQUEST_SAVE_SNAPSHOT_ROOT);
        }

        QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
            if (!memcmp(block->idstr, "pc.ram", 6)) {

                ram_block = (uint64_t)block->host;
                break;
            }
        }

        assert(ram_block != 0);

        once = false;
    }

    kvm_arch_get_registers_fast(cpu);
    env = &(X86_CPU(cpu))->env;

    uint64_t virt_addr = hypercall_arg & ~0xFFF; 

    uint64_t phys_addr = (hwaddr)get_paging_phys_addr(cpu, env->cr[3], virt_addr) & 0xFFFFFFFFFFFFF000ULL;
    uint64_t phys_addr_ram_offset = address_to_ram_offset(phys_addr);

    if(!(phys_addr_ram_offset < snapshot_page_blocklist_get_phys_area_size(get_fast_reload_snapshot()->blocklist))){

        printf("virt: %lx\n", virt_addr);
        printf("phys: %lx\n", phys_addr);
        printf("ram_offset: %lx\n", phys_addr_ram_offset);
        abort();
    }

    *((uint64_t*)(ram_block+phys_addr_ram_offset)) = virt_addr;

    if(ram_offset_to_address(phys_addr_ram_offset) != phys_addr){
        printf("phys: %lx\n", phys_addr);
        printf("ram_offset_to_address(phys_addr_ram_offset): %lx\n", ram_offset_to_address(phys_addr_ram_offset));
        abort();
    }
}

void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run,
                                              CPUState       *cpu,
                                              uint64_t        hypercall_arg)
{
    static bool first = true;
    Error *err = NULL;

    switch (hypercall_arg & 0xFFF) {
    case 0: /* create root snapshot */
        if (!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state,
                                  REQUEST_ROOT_EXISTS))
        {
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                   REQUEST_SAVE_SNAPSHOT_ROOT);
        }
        break;
    case 1: /* create tmp snapshot */
        if (!fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS))
        {
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                   REQUEST_SAVE_SNAPSHOT_TMP);
        }
        break;
    case 2: /* load root snapshot (+ discard tmp snapshot) */
        if (fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS))
        {
            reload_request_discard_tmp(GET_GLOBAL_STATE()->reload_state);
        }
        request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                               REQUEST_LOAD_SNAPSHOT_ROOT);
        meassure_performance();
        break;
    case 3: /* load tmp snapshot */
        if (fast_snapshot_exists(GET_GLOBAL_STATE()->reload_state, REQUEST_TMP_EXISTS))
        {
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                   REQUEST_LOAD_SNAPSHOT_TMP);
            meassure_performance();
        }
        break;
    case 5: // firefox debug hypercall
        if (first) {
            first = false;
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                   REQUEST_SAVE_SNAPSHOT_ROOT);
            // request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state, REQUEST_SAVE_SNAPSHOT_TMP);

            break;
        } else {
            request_fast_vm_reload(GET_GLOBAL_STATE()->reload_state,
                                   REQUEST_LOAD_SNAPSHOT_ROOT);
            break;
        }
    case 6: // kcore debug hypercall
        nyx_warn_once("%s: perform kcore_dump!\n", __func__);
        bool in_fuzzing_mode_state = GET_GLOBAL_STATE()->in_fuzzing_mode;
        GET_GLOBAL_STATE()->in_fuzzing_mode = true;        
	    qmp_dump_guest_memory(false, "file:/tmp/vmcore_test.img", true, 0, 0, 0,
			      0, 0, false, DUMP_GUEST_MEMORY_FORMAT_ELF, &err);
        if (err) {
            nyx_abort("(qmp_dump_guest_memory): %s\n", error_get_pretty(err));
        }
        GET_GLOBAL_STATE()->in_fuzzing_mode = in_fuzzing_mode_state;
        break;
    case 7: // virtual address to ramblock offset debug hypercall
        handle_hypercall_kafl_debug_virt_to_ram_offset(run, cpu, hypercall_arg);
        break;
    default:
        abort();
    }
}
#else /* NYX_ENABLE_DEBUG_HYPERCALLS */

void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run,
                                              CPUState       *cpu,
                                              uint64_t        hypercall_arg)
{
    nyx_abort("HYPERCALL_KAFL_DEBUG_TMP not enabled!\n");
}
#endif
