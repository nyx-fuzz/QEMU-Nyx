#pragma once
#include <stdint.h>

void     print_48_paging(uint64_t cr3);
void     kvm_nested_get_info(CPUState *cpu);
uint64_t get_nested_guest_rip(CPUState *cpu);
uint64_t get_nested_host_rip(CPUState *cpu);


uint64_t get_nested_host_cr3(CPUState *cpu);

void set_nested_rip(CPUState *cpu, uint64_t rip);
void print_configuration(FILE *stream, void *configuration, size_t size);