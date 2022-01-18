#include "nyx/synchronization.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/interface.h"
#include "nyx/fast_vm_reload.h"
#include "qemu-common.h"
#include "qemu/osdep.h"
#include "target/i386/cpu.h"
#include "sysemu/sysemu.h"
#include "sysemu/kvm.h"
#include "nyx/debug.h"
#include "nyx/state/state.h"
#include <sys/syscall.h>
#include <linux/kvm.h>
#include "qemu/main-loop.h"
#include "nyx/helpers.h"
#include "nyx/file_helper.h"


#include "pt.h"

pthread_mutex_t synchronization_lock_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t synchronization_lock_condition = PTHREAD_COND_INITIALIZER;
pthread_mutex_t synchronization_disable_pt_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile bool synchronization_reload_pending = false;
volatile bool synchronization_kvm_loop_waiting = false;


/* new SIGALRM based timeout detection */

//#define DEBUG_TIMEOUT_DETECTOR

void init_timeout_detector(timeout_detector_t* timeout_detector){
	timeout_detector->kvm_tid = 0;
	timeout_detector->reload_pending = false;
	timeout_detector->detection_enabled = false;

	timeout_detector->timeout_sec = 0;
	timeout_detector->timeout_usec = 0; /* default: disabled */

	timeout_detector->arm_timeout.it_interval.tv_sec = 0;
	timeout_detector->arm_timeout.it_interval.tv_usec = 0;
	timeout_detector->arm_timeout.it_value.tv_sec = 0;
	timeout_detector->arm_timeout.it_value.tv_usec = 0;

	timeout_detector->disarm_timeout.it_interval.tv_sec = 0;
	timeout_detector->disarm_timeout.it_interval.tv_usec = 0;
	timeout_detector->arm_timeout.it_value.tv_sec = timeout_detector->timeout_sec;
	timeout_detector->arm_timeout.it_value.tv_usec = timeout_detector->timeout_usec;

}

static void sigalarm_handler(int signum) {
		/* ensure that SIGALARM is ALWAYS handled by kvm thread */
    assert(GET_GLOBAL_STATE()->timeout_detector.kvm_tid == syscall(SYS_gettid));
		//GET_GLOBAL_STATE()->timeout_detector.reload_pending = true;
#ifdef DEBUG_TIMEOUT_DETECTOR
#endif
    //fprintf(stderr, "Handled! %d %ld\n", signum, syscall(SYS_gettid));
}

void install_timeout_detector(timeout_detector_t* timeout_detector){
		timeout_detector->kvm_tid = syscall(SYS_gettid);
    if(signal(SIGALRM, sigalarm_handler) == SIG_ERR) {
      fprintf(stderr, "%s failed!\n", __func__);
			assert(false);
    }
    //fprintf(stderr, "SIGALRM HANDLER INSTALLED! %ld\n", syscall(SYS_gettid));
}

void reset_timeout_detector(timeout_detector_t* timeout_detector){
#ifdef DEBUG_TIMEOUT_DETECTOR
    fprintf(stderr, "%s!\n", __func__);
#endif
	timeout_detector->reload_pending = false;
	if(timeout_detector->timeout_sec || timeout_detector->timeout_usec){
		timeout_detector->arm_timeout.it_value.tv_sec = timeout_detector->timeout_sec;
		timeout_detector->arm_timeout.it_value.tv_usec = timeout_detector->timeout_usec;
		timeout_detector->detection_enabled = true;
	}
	else{
			timeout_detector->detection_enabled = false;
	}
}

void enable_timeout_detector(timeout_detector_t* timeout_detector){
	timeout_detector->detection_enabled = true;
}

/*
static void disable_timeout_detector(timeout_detector_t* timeout_detector){
	timeout_detector->detection_enabled = false;

	struct itimerval tmp;

	timeout_detector->disarm_timeout.it_interval.tv_sec = 0;
	timeout_detector->disarm_timeout.it_interval.tv_usec = 0;
  assert(setitimer(ITIMER_REAL, &timeout_detector->disarm_timeout, &tmp) == 0);
}
*/


void update_itimer(timeout_detector_t* timeout_detector, uint8_t sec, uint32_t usec){
	//fprintf(stderr, "%s: %x %x\n", __func__, sec, usec);
	if(sec || usec){
		timeout_detector->timeout_sec = (time_t) sec;
		timeout_detector->timeout_usec = (suseconds_t) usec;
		timeout_detector->detection_enabled = true;
	}
	else{
		timeout_detector->detection_enabled = false;
	}
}

bool arm_sigprof_timer(timeout_detector_t* timeout_detector){
	//return false;
    if(timeout_detector->detection_enabled){
			if(timeout_detector->reload_pending || (!timeout_detector->arm_timeout.it_value.tv_sec && !timeout_detector->arm_timeout.it_value.tv_usec)){
					//assert(false);
					fprintf(stderr, "TIMER EXPIRED 1! %d %ld %ld\n", timeout_detector->reload_pending, timeout_detector->arm_timeout.it_value.tv_sec, timeout_detector->arm_timeout.it_value.tv_usec);
					reset_timeout_detector(timeout_detector);
					/* TODO: check if this function still works as expected even if we don't return at this point */
					//return true;
			}
#ifdef DEBUG_TIMEOUT_DETECTOR
				fprintf(stderr, "%s (%ld %ld)\n", __func__, timeout_detector->arm_timeout.it_value.tv_sec, timeout_detector->arm_timeout.it_value.tv_usec);
#endif
				timeout_detector->arm_timeout.it_interval.tv_sec = 0;
				timeout_detector->arm_timeout.it_interval.tv_usec = 0;


        assert(setitimer(ITIMER_REAL, &timeout_detector->arm_timeout, 0) == 0);
    }
		return false;
}

bool disarm_sigprof_timer(timeout_detector_t* timeout_detector){
	//return false;
		struct itimerval tmp;

    if(timeout_detector->detection_enabled){
				timeout_detector->disarm_timeout.it_interval.tv_sec = 0;
				timeout_detector->disarm_timeout.it_interval.tv_usec = 0;
        assert(setitimer(ITIMER_REAL, &timeout_detector->disarm_timeout, &tmp) == 0);

				timeout_detector->arm_timeout.it_value.tv_sec = tmp.it_value.tv_sec;
				timeout_detector->arm_timeout.it_value.tv_usec = tmp.it_value.tv_usec;

#ifdef DEBUG_TIMEOUT_DETECTOR
				fprintf(stderr, "%s (%ld %ld)\n", __func__, timeout_detector->arm_timeout.it_value.tv_sec, timeout_detector->arm_timeout.it_value.tv_usec);
#endif
			if(timeout_detector->reload_pending || (!timeout_detector->arm_timeout.it_value.tv_sec && !timeout_detector->arm_timeout.it_value.tv_usec)){
					//fprintf(stderr, "TIMER EXPIRED 2! %d %d %d\n", timeout_detector->reload_pending, timeout_detector->arm_timeout.it_value.tv_sec, timeout_detector->arm_timeout.it_value.tv_usec);
	
					reset_timeout_detector(timeout_detector);
					//timeout_detector->detection_enabled = false;
					return true;
			}
	  }
    return false;
}

void block_signals(void){
  sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGABRT);
	sigaddset(&set, SIGSEGV);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
	//fprintf(stderr, "%s!\n", __func__);

}

void unblock_signals(void){
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIGABRT);
	sigaddset(&set, SIGSEGV);
	sigaddset(&set, SIGALRM);
	sigprocmask(SIG_UNBLOCK, &set, NULL);
	//fprintf(stderr, "%s!\n", __func__);
}

/* -------------------- */

static inline void handle_tmp_snapshot_state(void){
	if(GET_GLOBAL_STATE()->discard_tmp_snapshot){
		if(fast_reload_tmp_created(get_fast_reload_snapshot())){
			qemu_mutex_lock_iothread();
			fast_reload_discard_tmp_snapshot(get_fast_reload_snapshot()); /* bye bye */
			qemu_mutex_unlock_iothread();
			//fprintf(stderr, "======= SNAPSHOT REMOVED! =======\n");
		}
		GET_GLOBAL_STATE()->discard_tmp_snapshot = false;
		set_tmp_snapshot_created(GET_GLOBAL_STATE()->auxilary_buffer, 0);
	}
}

static inline bool synchronization_check_page_not_found(void){
	bool failure = false;

	/* a page is missing in the current execution */
	if(GET_GLOBAL_STATE()->decoder_page_fault){		
		set_page_not_found_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, GET_GLOBAL_STATE()->decoder_page_fault_addr);
		GET_GLOBAL_STATE()->decoder_page_fault = false;
		GET_GLOBAL_STATE()->decoder_page_fault_addr = 0;
		failure = true;
	}

	/* page was dumped during this execution */
	if(GET_GLOBAL_STATE()->dump_page){
		kvm_remove_all_breakpoints(qemu_get_cpu(0));
		kvm_vcpu_ioctl(qemu_get_cpu(0), KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
		kvm_vcpu_ioctl(qemu_get_cpu(0), KVM_VMX_PT_DISABLE_MTF);
		reset_page_not_found_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
		failure = true;
	}

	return failure;
}

void synchronization_unlock(void){
	//fprintf(stderr, "%s\n", __func__);

	pthread_mutex_lock(&synchronization_lock_mutex);
	pthread_cond_signal(&synchronization_lock_condition);
	//hypercall_reset_hprintf_counter();
	pthread_mutex_unlock(&synchronization_lock_mutex);
}


uint64_t run_counter = 0;
bool in_fuzzing_loop = false;

//bool last_timeout = false;

void synchronization_lock_hprintf(void){
	pthread_mutex_lock(&synchronization_lock_mutex);
	interface_send_char(NYX_INTERFACE_PING);

	pthread_cond_wait(&synchronization_lock_condition, &synchronization_lock_mutex);
	pthread_mutex_unlock(&synchronization_lock_mutex);
}
void synchronization_lock(void){

	pthread_mutex_lock(&synchronization_lock_mutex);
	run_counter++;

	if(qemu_get_cpu(0)->intel_pt_run_trashed){
		set_pt_overflow_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
	}
	set_exec_done_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer,
											GET_GLOBAL_STATE()->timeout_detector.timeout_sec - GET_GLOBAL_STATE()->timeout_detector.arm_timeout.it_value.tv_sec,
											GET_GLOBAL_STATE()->timeout_detector.timeout_usec - (uint32_t)GET_GLOBAL_STATE()->timeout_detector.arm_timeout.it_value.tv_usec,
											GET_GLOBAL_STATE()->num_dirty_pages);
	/*
	if(last_timeout){
		reset_timeout_detector_timeout(&(GET_GLOBAL_STATE()->timeout_detector));
	}
	else{
		*/
	reset_timeout_detector(&(GET_GLOBAL_STATE()->timeout_detector));
	//}

	if(synchronization_check_page_not_found()){
		set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
	}

	if(GET_GLOBAL_STATE()->dump_page){
		GET_GLOBAL_STATE()->dump_page = false;
		GET_GLOBAL_STATE()->dump_page_addr = 0x0;
		kvm_remove_all_breakpoints(qemu_get_cpu(0));
		kvm_vcpu_ioctl(qemu_get_cpu(0), KVM_VMX_PT_DISABLE_PAGE_DUMP_CR3);
	}

	//last_timeout = false;

	if(unlikely(GET_GLOBAL_STATE()->in_redqueen_reload_mode || GET_GLOBAL_STATE()->redqueen_state->trace_mode)){
		if(GET_GLOBAL_STATE()->redqueen_state->trace_mode){
			write_trace_result(GET_GLOBAL_STATE()->redqueen_state->trace_state);
			redqueen_trace_reset(GET_GLOBAL_STATE()->redqueen_state->trace_state);
		}
		fsync_all_traces();		
	}

	interface_send_char(NYX_INTERFACE_PING);

	pthread_cond_wait(&synchronization_lock_condition, &synchronization_lock_mutex);
	pthread_mutex_unlock(&synchronization_lock_mutex);

	check_auxiliary_config_buffer(GET_GLOBAL_STATE()->auxilary_buffer, &GET_GLOBAL_STATE()->shadow_config);
	set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 1);

	GET_GLOBAL_STATE()->pt_trace_size = 0;
	/*
	if(GET_GLOBAL_STATE()->dump_page){
		fprintf(stderr, "DISABLING TIMEOUT DETECTION\n");
		disable_timeout_detector(&(GET_GLOBAL_STATE()->timeout_detector));
	}
	*/

}

static void perform_reload(void){
	if(fast_reload_root_created(get_fast_reload_snapshot())){
		qemu_mutex_lock_iothread();
		fast_reload_restore(get_fast_reload_snapshot());
		qemu_mutex_unlock_iothread();
		set_reload_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
		set_result_dirty_pages(GET_GLOBAL_STATE()->auxilary_buffer, get_dirty_page_num(get_fast_reload_snapshot()));
	}
	else{
		fprintf(stderr, "WARNING: Root snapshot is not available yet!\n");
	}
}

void synchronization_lock_crash_found(void){
	if(!in_fuzzing_loop && GET_GLOBAL_STATE()->in_fuzzing_mode){
		fprintf(stderr, "<%d-%ld>\t%s [NOT IN FUZZING LOOP] at %lx\n", getpid(), run_counter, __func__, get_rip(qemu_get_cpu(0)));
		//abort();
	}

	pt_disable(qemu_get_cpu(0), false);

	handle_tmp_snapshot_state();

	set_crash_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
	
	perform_reload();

	//synchronization_lock();

	in_fuzzing_loop = false;
}

void synchronization_lock_timeout_found(void){		
	
	//fprintf(stderr, "<%d>\t%s\n", getpid(), __func__);

	if(!in_fuzzing_loop){
		//fprintf(stderr, "<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
		set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
	}	

	pt_disable(qemu_get_cpu(0), false);

	handle_tmp_snapshot_state();

	set_timeout_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);
	reset_timeout_detector(&(GET_GLOBAL_STATE()->timeout_detector));

	perform_reload();

	in_fuzzing_loop = false;
}

void synchronization_lock_shutdown_detected(void){
	if(!in_fuzzing_loop){
		fprintf(stderr, "<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
		set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
	}

	pt_disable(qemu_get_cpu(0), false);

	handle_tmp_snapshot_state();

	perform_reload();

	in_fuzzing_loop = false;
	//synchronization_lock();
}

void synchronization_payload_buffer_write_detected(void){
	static char reason[1024];

	if(!in_fuzzing_loop){
			fprintf(stderr, "<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
	}
	
	pt_disable(qemu_get_cpu(0), false);

	handle_tmp_snapshot_state();

	int bytes = snprintf(reason, 1024, "Payload buffer write attempt at RIP: %lx\n", get_rip(qemu_get_cpu(0)));
	set_payload_buffer_write_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, reason, bytes);
	set_reload_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer);

	perform_reload();

	in_fuzzing_loop = false;
	//synchronization_lock();
}

void synchronization_cow_full_detected(void){
	if(!in_fuzzing_loop){
			fprintf(stderr, "<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
	}

	pt_disable(qemu_get_cpu(0), false);

	handle_tmp_snapshot_state();

	perform_reload();

	in_fuzzing_loop = false;
	//synchronization_lock();
}

void synchronization_disable_pt(CPUState *cpu){
	//fprintf(stderr, "==============> %s\n", __func__);
	if(!in_fuzzing_loop){
		//fprintf(stderr, "<%d-%ld>\t%s [NOT IN FUZZING LOOP]\n", getpid(), run_counter, __func__);
		set_success_auxiliary_result_buffer(GET_GLOBAL_STATE()->auxilary_buffer, 0);
		/*
		qemu_backtrace();
		while(1){

		}
		*/
	}

	pt_disable(qemu_get_cpu(0), false);

	handle_tmp_snapshot_state();

	if(GET_GLOBAL_STATE()->in_reload_mode || GET_GLOBAL_STATE()->in_redqueen_reload_mode || GET_GLOBAL_STATE()->dump_page || fast_reload_tmp_created(get_fast_reload_snapshot())){
		perform_reload();
	}

	set_result_pt_trace_size(GET_GLOBAL_STATE()->auxilary_buffer, GET_GLOBAL_STATE()->pt_trace_size);
	set_result_bb_coverage(GET_GLOBAL_STATE()->auxilary_buffer, GET_GLOBAL_STATE()->bb_coverage);


	

	in_fuzzing_loop = false;
}

void synchronization_enter_fuzzing_loop(CPUState *cpu){
	if (pt_enable(cpu, false) == 0){
		cpu->pt_enabled = true;
	}
	in_fuzzing_loop = true;

	reset_timeout_detector(&(GET_GLOBAL_STATE()->timeout_detector));
	//enable_timeout_detector(&(GET_GLOBAL_STATE()->timeout_detector));
}

