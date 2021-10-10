#pragma once 

/* HyperTrash! */
void handle_hypercall_kafl_nested_hprintf(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_prepare(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_acquire(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_nested_early_release(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);