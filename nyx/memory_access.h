/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef MEMORY_ACCESS_H
#define MEMORY_ACCESS_H

#include "sysemu/kvm_int.h"
#include "qemu-common.h"
#include "nyx/types.h"
#include <linux/kvm.h>


mem_mode_t get_current_mem_mode(CPUState *cpu);

uint64_t get_paging_phys_addr(CPUState *cpu, uint64_t cr3, uint64_t addr);

bool read_physical_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu);
bool write_physical_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu);

bool remap_payload_slot(uint64_t phys_addr, uint32_t slot, CPUState *cpu);
bool remap_payload_slot_protected(uint64_t phys_addr, uint32_t slot, CPUState *cpu);
bool remap_payload_buffer(uint64_t virt_guest_addr, CPUState *cpu);

bool remap_slots(uint64_t  addr,
                 uint32_t  slots,
                 CPUState *cpu,
                 int       fd,
                 uint64_t  shm_size,
                 bool virtual,
                 uint64_t cr3);
bool remap_slot(uint64_t  addr,
                uint32_t  slot,
                CPUState *cpu,
                int       fd,
                uint64_t  shm_size,
                bool virtual,
                uint64_t cr3);

bool read_virtual_memory_cr3(
    uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu, uint64_t cr3);

bool read_virtual_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu);
bool write_virtual_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu);
void hexdump_virtual_memory(uint64_t address, uint32_t size, CPUState *cpu);
bool is_addr_mapped(uint64_t address, CPUState *cpu);
bool is_addr_mapped_cr3(uint64_t address, CPUState *cpu, uint64_t cr3);

int  insert_breakpoint(CPUState *cpu, uint64_t addr, uint64_t len);
int  remove_breakpoint(CPUState *cpu, uint64_t addr, uint64_t len);
void remove_all_breakpoints(CPUState *cpu);

uint64_t disassemble_at_rip(int fd, uint64_t address, CPUState *cpu, uint64_t cr3);
bool dump_page_cr3_snapshot(uint64_t address, uint8_t *data, CPUState *cpu, uint64_t cr3);
bool dump_page_cr3_ht(uint64_t address, uint8_t *data, CPUState *cpu, uint64_t cr3);
bool is_addr_mapped_cr3_snapshot(uint64_t address, CPUState *cpu, uint64_t cr3);

void print_48_pagetables(uint64_t cr3);

bool dump_page_ht(uint64_t address, uint8_t *data, CPUState *cpu);

void resize_shared_memory(uint32_t new_size, uint32_t *shm_size, void **shm_ptr, int fd);

#endif
