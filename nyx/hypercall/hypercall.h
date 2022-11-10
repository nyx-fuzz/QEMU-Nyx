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

#pragma once

#include <stdint.h>

#define PAYLOAD_BUFFER_SIZE_64 26
#define PAYLOAD_BUFFER_SIZE_32 20

// FIXME: move to common nyx.h
#define KAFL_MODE_64 0
#define KAFL_MODE_32 1
#define KAFL_MODE_16 2

typedef struct {
    uint64_t ip[4];
    uint64_t size[4];
    uint8_t  enabled[4];
} kAFL_ranges;

bool check_bitmap_byte(uint32_t value);

// #define PANIC_DEBUG

/*
 * Panic Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 08 00 00 00    mov    rbx,0x8
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define PANIC_PAYLOAD_64                                                           \
    "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x08\x00\x00\x00\x48\xC7\xC1\x00" \
    "\x00\x00\x00\x0F\x01\xC1\xF4"

/*
 * Panic Notifier Payload (x86-32)
 * fa                      cli
 * b8 1f 00 00 00          mov    $0x1f,%eax
 * bb 08 00 00 00          mov    $0x8,%ebx
 * b9 00 00 00 00          mov    $0x0,%ecx
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define PANIC_PAYLOAD_32                                                           \
    "\xFA\xB8\x1F\x00\x00\x00\xBB\x08\x00\x00\x00\xB9\x00\x00\x00\x00\x0F\x01\xC1" \
    "\xF4"

/*
 * KASAN Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 09 00 00 00    mov    rbx,0x9
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define KASAN_PAYLOAD_64                                                           \
    "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x09\x00\x00\x00\x48\xC7\xC1\x00" \
    "\x00\x00\x00\x0F\x01\xC1\xF4"

/*
 * KASAN Notifier Payload (x86-32)
 * fa                      cli
 * b8 1f 00 00 00          mov    $0x1f,%eax
 * bb 09 00 00 00          mov    $0x9,%ebx
 * b9 00 00 00 00          mov    $0x0,%ecx
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define KASAN_PAYLOAD_32                                                           \
    "\xFA\xB8\x1F\x00\x00\x00\xBB\x09\x00\x00\x00\xB9\x00\x00\x00\x00\x0F\x01\xC1" \
    "\xF4"

void pt_setup_program(void *ptr);
void pt_setup_snd_handler(void (*tmp)(char, void *), void *tmp_s);
void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end);
void pt_setup_enable_hypercalls(void);

void pt_disable_wrapper(CPUState *cpu);

void hypercall_submit_address(uint64_t address);
bool hypercall_check_tuple(uint64_t current_addr, uint64_t prev_addr);

bool hypercall_check_transition(uint64_t value);
void hypercall_submit_transition(uint32_t value);

void hypercall_enable_filter(void);
void hypercall_disable_filter(void);
void hypercall_commit_filter(void);

bool pt_hypercalls_enabled(void);

void hypercall_unlock(void);
void hypercall_reload(void);

void handle_hypercall_kafl_acquire(struct kvm_run *run,
                                   CPUState       *cpu,
                                   uint64_t        hypercall_arg);
void handle_hypercall_kafl_release(struct kvm_run *run,
                                   CPUState       *cpu,
                                   uint64_t        hypercall_arg);
void handle_hypercall_kafl_panic(struct kvm_run *run,
                                 CPUState       *cpu,
                                 uint64_t        hypercall_arg);

void handle_hypercall_kafl_page_dump_bp(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg,
                                        uint64_t        page);


void hprintf(char *msg);

bool handle_hypercall_kafl_next_payload(struct kvm_run *run,
                                        CPUState       *cpu,
                                        uint64_t        hypercall_arg);
void hypercall_reset_hprintf_counter(void);

bool handle_hypercall_kafl_hook(struct kvm_run *run,
                                CPUState       *cpu,
                                uint64_t        hypercall_arg);
void handle_hypercall_kafl_mtf(struct kvm_run *run,
                               CPUState       *cpu,
                               uint64_t        hypercall_arg);
void pt_enable_rqo(CPUState *cpu);
void pt_disable_rqo(CPUState *cpu);
void pt_enable_rqi(CPUState *cpu);
void pt_disable_rqi(CPUState *cpu);
void pt_set_redqueen_instrumentation_mode(CPUState *cpu,
                                          int       redqueen_instruction_mode);
void pt_set_redqueen_update_blacklist(CPUState *cpu, bool newval);
void pt_set_enable_patches_pending(CPUState *cpu);
void pt_set_disable_patches_pending(CPUState *cpu);

void create_fast_snapshot(CPUState *cpu, bool nested);
int  handle_kafl_hypercall(struct kvm_run *run,
                           CPUState       *cpu,
                           uint64_t        hypercall,
                           uint64_t        arg);

void skip_init(void);

typedef struct kafl_dump_file_s {
    uint64_t file_name_str_ptr;
    uint64_t data_ptr;
    uint64_t bytes;
    uint8_t  append;
} __attribute__((packed)) kafl_dump_file_t;

typedef struct req_data_bulk_s {
    char     file_name[256];
    uint64_t num_addresses;
    uint64_t addresses[479];
} __attribute__((packed)) req_data_bulk_t;
