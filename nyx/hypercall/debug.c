#include "qemu/osdep.h"

#include "sysemu/kvm.h"
#include <sys/time.h>

#include "nyx/fast_vm_reload.h"
#include "nyx/hypercall/debug.h"
#include "nyx/state/state.h"
#include "nyx/synchronization.h"

// #define NYX_ENABLE_DEBUG_HYPERCALLS
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

void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run,
                                              CPUState       *cpu,
                                              uint64_t        hypercall_arg)
{
    static bool first = true;

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
