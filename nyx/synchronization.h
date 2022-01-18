#pragma once

#include "qemu/osdep.h"
#include <linux/kvm.h>

typedef struct timeout_detector_s{
	int kvm_tid;
	volatile bool reload_pending; 
	volatile bool detection_enabled; 

  time_t      timeout_sec;
  suseconds_t timeout_usec; 

	struct itimerval arm_timeout;
	struct itimerval disarm_timeout;

	struct timespec start_time;
	struct timespec end_time;
} timeout_detector_t;

void init_timeout_detector(timeout_detector_t* timeout_detector);
void install_timeout_detector(timeout_detector_t* timeout_detector);
void reset_timeout_detector(timeout_detector_t* timeout_detector);
bool arm_sigprof_timer(timeout_detector_t* timeout_detector);
bool disarm_sigprof_timer(timeout_detector_t* timeout_detector);

void update_itimer(timeout_detector_t* timeout_detector, uint8_t sec, uint32_t usec);

void block_signals(void);
void unblock_signals(void);


void synchronization_unlock(void);

void synchronization_lock_hprintf(void);


void synchronization_lock(void);
void synchronization_lock_crash_found(void);
void synchronization_lock_timeout_found(void);
void synchronization_lock_shutdown_detected(void);
void synchronization_cow_full_detected(void);
void synchronization_disable_pt(CPUState *cpu);
void synchronization_enter_fuzzing_loop(CPUState *cpu);
void synchronization_payload_buffer_write_detected(void);

void enable_timeout_detector(timeout_detector_t* timeout_detector);
void reset_timeout_detector_timeout(timeout_detector_t* timeout_detector);