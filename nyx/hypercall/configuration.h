#pragma once

#include "qemu/osdep.h"
#include <stdint.h>
#include "nyx/types.h"

void handle_hypercall_kafl_get_host_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_set_agent_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);

