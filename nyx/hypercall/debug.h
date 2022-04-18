#pragma once

void handle_hypercall_kafl_debug(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);