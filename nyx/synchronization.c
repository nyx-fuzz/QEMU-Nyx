#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"
#include "qemu-common.h"
#include "nyx/synchronization.h"
#include "nyx/debug.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/file_helper.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/interface.h"
#include "nyx/state/state.h"
#include <linux/kvm.h>
#include <sys/syscall.h>


#include "pt.h"

pthread_mutex_t synchronization_lock_mutex       = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  synchronization_lock_condition   = PTHREAD_COND_INITIALIZER;
pthread_mutex_t synchronization_disable_pt_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile bool synchronization_reload_pending   = false;
volatile bool synchronization_kvm_loop_waiting = false;


/* SIGALRM based timeout detection */
// #define DEBUG_TIMEOUT_DETECTOR

void init_timeout_detector(timeout_detector_t *timer)
{
    timer->kvm_tid           = 0;
    timer->detection_enabled = false;

    timer->config.tv_sec  = 0;
    timer->config.tv_usec = 0;

    timer->alarm.it_interval.tv_sec  = 0;
    timer->alarm.it_interval.tv_usec = 0;
    timer->alarm.it_value.tv_sec     = 0;
    timer->alarm.it_value.tv_usec    = 0;
}

static void sigalarm_handler(int signum)
{
    /* ensure that SIGALARM is ALWAYS handled by kvm thread */
    assert(GET_GLOBAL_STATE()->timeout_detector.kvm_tid == syscall(SYS_gettid));
#ifdef DEBUG_TIMEOUT_DETECTOR
    nyx_debug("Handled! %d %ld\n", signum, syscall(SYS_gettid));
#endif
}

void install_timeout_detector(timeout_detector_t *timer)
{
    timer->kvm_tid = syscall(SYS_gettid);
    if (signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
        nyx_debug("%s failed!\n", __func__);
        assert(false);
    }
#ifdef DEBUG_TIMEOUT_DETECTOR
    nyx_debug("SIGALRM HANDLER INSTALLED! tid=%ld\n", syscall(SYS_gettid));
#endif
}

void reset_timeout_detector(timeout_detector_t *timer)
{
#ifdef DEBUG_TIMEOUT_DETECTOR
    nyx_debug("%s!\n", __func__);
#endif

    if (timer->config.tv_sec || timer->config.tv_usec) {
        timer->alarm.it_value.tv_sec  = timer->config.tv_sec;
        timer->alarm.it_value.tv_usec = timer->config.tv_usec;
        timer->detection_enabled      = true;
    } else {
        timer->detection_enabled = false;
    }
}

void update_itimer(timeout_detector_t *timer, uint8_t sec, uint32_t usec)
{
#ifdef DEBUG_TIMEOUT_DETECTOR
    nyx_debug("%s: %x %x\n", __func__, sec, usec);
#endif

    if (sec || usec) {
        timer->config.tv_sec     = (time_t)sec;
        timer->config.tv_usec    = (suseconds_t)usec;
        timer->detection_enabled = true;
    } else {
        timer->detection_enabled = false;
    }
}

void arm_sigprof_timer(timeout_detector_t *timer)
{
#ifdef DEBUG_TIMEOUT_DETECTOR
    nyx_debug("%s (%ld %ld)\n", __func__, timer->alarm.it_value.tv_sec,
              timer->alarm.it_value.tv_usec);
#endif

    if (timer->detection_enabled) {
        if (timer->alarm.it_value.tv_usec == 0 && timer->alarm.it_value.tv_sec == 0) {
            nyx_warn("Attempt to re-arm an expired timer! => reset(%ld.%ld)\n",
                     timer->config.tv_sec, timer->config.tv_usec);
            reset_timeout_detector(timer);
        }
        assert(setitimer(ITIMER_REAL, &timer->alarm, NULL) == 0);
    }
}

bool disarm_sigprof_timer(timeout_detector_t *timer)
{
#ifdef DEBUG_TIMEOUT_DETECTOR
    nyx_debug("%s (%ld %ld)\n", __func__, timer->alarm.it_value.tv_sec,
              timer->alarm.it_value.tv_usec);
#endif

    if (timer->detection_enabled) {
        struct itimerval disable = { 0 };
        assert(setitimer(ITIMER_REAL, &disable, &timer->alarm) == 0);
        assert(timer->alarm.it_interval.tv_usec == 0);

        if (timer->alarm.it_value.tv_usec == 0 && timer->alarm.it_value.tv_sec == 0) {
            reset_timeout_detector(timer);
            return true;
        }
    }
    return false;
}

void block_signals(void)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGABRT);
    sigaddset(&set, SIGSEGV);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

void unblock_signals(void)
{
    sigset_t set;

    sigemptyset(&set);
    sigaddset(&set, SIGABRT);
    sigaddset(&set, SIGSEGV);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

/* -------------------- */

static inline void handle_tmp_snapshot_state(void)
{
    if (GET_GLOBAL_STATE()->discard_tmp_snapshot) {
        if (fast_reload_tmp_created(get_fast_reload_snapshot())) {
            qemu_mutex_lock_iothread();
            fast_reload_discard_tmp_snapshot(get_fast_reload_snapshot()); /* bye bye */
            qemu_mutex_unlock_iothread();
            // nyx_debug("======= SNAPSHOT REMOVED! =======\n");
        }
        GET_GLOBAL_STATE()->discard_tmp_snapshot = false;
        set_tmp_snapshot_created(GET_GLOBAL_STATE()->auxilary_buffer, 0);
    }
}

static inline bool synchronization_check_page_not_found(void)
{
    bool failure = false;

    /* a page is missing in the current execution */
    if (GET_GLOBAL_STATE()->decoder_page_fault) {
        set_page_not_found_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                         GET_GLOBAL_STATE()->decoder_page_fault_addr);
        GET_GLOBAL_STATE()->decoder_page_fault      = false;
        GET_GLOBAL_STATE()->decoder_page_fault_addr = 0;
        failure                                     = true;
    }

    /* page was dumped during this execution */
    if (GET_GLOBAL_STATE()->dump_page) {
        kvm_remove_all_breakpoints(qemu_get_cpu(0));
        kvm_vcpu_ioctl(qemu_get_cpu(0), KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
        kvm_vcpu_ioctl(qemu_get_cpu(0), KVM_VMX_PT_DISABLE_MTF);
        reset_page_not_found_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
        failure = true;
    }

    return failure;
}

void synchronization_unlock(void)
{
    // nyx_debug("%s\n", __func__);

    pthread_mutex_lock(&synchronization_lock_mutex);
    pthread_cond_signal(&synchronization_lock_condition);
    pthread_mutex_unlock(&synchronization_lock_mutex);
}


uint64_t run_counter     = 0;
bool     in_fuzzing_loop = false;

void synchronization_lock_hprintf(void)
{
    pthread_mutex_lock(&synchronization_lock_mutex);
    interface_send_char(NYX_INTERFACE_PING);

    pthread_cond_wait(&synchronization_lock_condition, &synchronization_lock_mutex);
    pthread_mutex_unlock(&synchronization_lock_mutex);
}
void synchronization_lock(void)
{
    timeout_detector_t timer = GET_GLOBAL_STATE()->timeout_detector;
    pthread_mutex_lock(&synchronization_lock_mutex);
    run_counter++;

    long runtime_sec  = timer.config.tv_sec - timer.alarm.it_value.tv_sec;
    long runtime_usec = timer.config.tv_usec - timer.alarm.it_value.tv_usec;

    if (runtime_usec < 0) {
        if (runtime_sec < 1) {
            nyx_warn("negative payload runtime?!\n");
        }
        runtime_sec -= 1;
        runtime_usec = timer.config.tv_usec - timer.alarm.it_value.tv_usec + 1000000;
    }
    set_exec_done_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                          runtime_sec, runtime_usec,
                                          GET_GLOBAL_STATE()->num_dirty_pages);

    if (synchronization_check_page_not_found()) {
        set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
    }

    if (qemu_get_cpu(0)->intel_pt_run_trashed) {
        set_pt_overflow_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
        qemu_get_cpu(0)->intel_pt_run_trashed = false;
    }

    if (GET_GLOBAL_STATE()->dump_page) {
        GET_GLOBAL_STATE()->dump_page      = false;
        GET_GLOBAL_STATE()->dump_page_addr = 0x0;
        kvm_remove_all_breakpoints(qemu_get_cpu(0));
        kvm_vcpu_ioctl(qemu_get_cpu(0), KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
    }

    if (unlikely(GET_GLOBAL_STATE()->in_redqueen_reload_mode)) {
        fsync_redqueen_files();
    }

    if (unlikely(GET_GLOBAL_STATE()->trace_mode)) {
        redqueen_trace_flush();
    }

    interface_send_char(NYX_INTERFACE_PING);

    pthread_cond_wait(&synchronization_lock_condition, &synchronization_lock_mutex);
    pthread_mutex_unlock(&synchronization_lock_mutex);

    check_auxiliary_config_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                  &GET_GLOBAL_STATE()->shadow_config);

    set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 1);
    reset_pt_overflow_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);

    GET_GLOBAL_STATE()->pt_trace_size = 0;
}

static void perform_reload(void)
{
    if (fast_reload_root_created(get_fast_reload_snapshot())) {
        qemu_mutex_lock_iothread();
        fast_reload_restore(get_fast_reload_snapshot());
        qemu_mutex_unlock_iothread();
        set_reload_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
        set_result_dirty_pages(GET_GLOBAL_STATE()->auxilary_buffer,
                               get_dirty_page_num(get_fast_reload_snapshot()));
    } else {
        nyx_warn("Root snapshot is not available yet!\n");
    }
}

void synchronization_lock_crash_found(void)
{
    if (!in_fuzzing_loop && GET_GLOBAL_STATE()->in_fuzzing_mode) {
        nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP] at %lx\n", getpid(),
                 run_counter, __func__, get_rip(qemu_get_cpu(0)));
        // abort();
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    set_crash_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);

    perform_reload();

    in_fuzzing_loop = false;
}

void synchronization_lock_asan_found(void)
{
    if (!in_fuzzing_loop) {
        nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter,
                 __func__);
        set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    set_asan_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);

    perform_reload();

    in_fuzzing_loop = false;
}

void synchronization_lock_timeout_found(void)
{
    // nyx_debug("<%d>\t%s\n", getpid(), __func__);

    if (!in_fuzzing_loop) {
        // nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
        set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    set_timeout_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);

    perform_reload();

    in_fuzzing_loop = false;
}

void synchronization_lock_shutdown_detected(void)
{
    if (!in_fuzzing_loop) {
        nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter,
                 __func__);
        set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    perform_reload();

    in_fuzzing_loop = false;
}

void synchronization_payload_buffer_write_detected(void)
{
    static char reason[1024];

    if (!in_fuzzing_loop) {
        nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter,
                 __func__);
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    int bytes = snprintf(reason, 1024, "Payload buffer write attempt at RIP: %lx\n",
                         get_rip(qemu_get_cpu(0)));
    set_payload_buffer_write_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
                                                     reason, bytes);
    set_reload_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);

    perform_reload();

    in_fuzzing_loop = false;
}

void synchronization_cow_full_detected(void)
{
    if (!in_fuzzing_loop) {
        nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter,
                 __func__);
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    perform_reload();

    in_fuzzing_loop = false;
}

void synchronization_disable_pt(CPUState *cpu)
{
    // nyx_trace();
    if (!in_fuzzing_loop) {
        // nyx_warn("<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
        set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
    }

    pt_disable(qemu_get_cpu(0), false);

    handle_tmp_snapshot_state();

    if (GET_GLOBAL_STATE()->in_reload_mode ||
        GET_GLOBAL_STATE()->in_redqueen_reload_mode || GET_GLOBAL_STATE()->dump_page ||
        fast_reload_tmp_created(get_fast_reload_snapshot()))
    {
        perform_reload();
    }

    set_result_pt_trace_size(GET_GLOBAL_STATE()->auxilary_buffer,
                             GET_GLOBAL_STATE()->pt_trace_size);
    set_result_bb_coverage(GET_GLOBAL_STATE()->auxilary_buffer,
                           GET_GLOBAL_STATE()->bb_coverage);

    if (GET_GLOBAL_STATE()->starved == true)
        set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 2);

    in_fuzzing_loop = false;
}

void synchronization_enter_fuzzing_loop(CPUState *cpu)
{
    if (pt_enable(cpu, false) == 0) {
        cpu->pt_enabled = true;
    }
    in_fuzzing_loop = true;

    reset_timeout_detector(&(GET_GLOBAL_STATE()->timeout_detector));
}
