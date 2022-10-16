#pragma once

#include "sysemu/kvm.h"
#include <stdint.h>

void handle_hypercall_kafl_debug_tmp_snapshot(struct kvm_run *run,
                                              CPUState       *cpu,
                                              uint64_t        hypercall_arg);