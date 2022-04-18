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

#ifndef REDQUEEN_H
#define REDQUEEN_H

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "qemu/osdep.h"
#include <linux/kvm.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include "redqueen_trace.h"
#include "khash.h"
#include "page_cache.h"

//#define RQ_DEBUG

#define REDQUEEN_MAX_STRCMP_LEN 64
#define REDQUEEN_TRAP_LIMIT	16

#define REG64_NUM 16
#define REG32_NUM 16
//seems we don't want to include rip, since this index is used to acces the qemu cpu structure or something?
#define REG16_NUM 16 
#define REG8L_NUM 16
#define REG8H_NUM  8

#define EXTRA_REG_RIP 16
#define EXTRA_REG_NOP 17

#define REDQUEEN_NO_INSTRUMENTATION 0
#define REDQUEEN_LIGHT_INSTRUMENTATION 1
#define REDQUEEN_SE_INSTRUMENTATION 2
#define REDQUEEN_WHITELIST_INSTRUMENTATION 3

enum reg_types{RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15};

#define CMP_BITMAP_NOP					0x0000000UL  
#define CMP_BITMAP_RQ_INSTRUCTION			0x1000000UL 
#define CMP_BITMAP_SE_INSTRUCTION			0x2000000UL
#define CMP_BITMAP_BLACKLISTED	  			0x4000000UL
#define CMP_BITMAP_TRACE_ENABLED  			0x8000000UL
#define CMP_BITMAP_SHOULD_HOOK_SE 			(CMP_BITMAP_SE_INSTRUCTION|CMP_BITMAP_TRACE_ENABLED)
#define CMP_BITMAP_SHOULD_HOOK_RQ 			(CMP_BITMAP_RQ_INSTRUCTION)

KHASH_MAP_INIT_INT64(RQ, uint32_t)

typedef struct redqueen_s{
	khash_t(RQ) *lookup;
	bool intercept_mode;
	bool singlestep_enabled;
	int hooks_applied;
	CPUState *cpu;
	uint64_t last_rip;
	uint64_t next_rip;
  uint64_t *breakpoint_whitelist;
  uint64_t num_breakpoint_whitelist;
  redqueen_trace_t* trace_state; 
  page_cache_t* page_cache;
} redqueen_t;

typedef struct redqueen_workdir_s{
  char* redqueen_results;
  char* symbolic_results;
  char* pt_trace_results;
  char* redqueen_patches;
  char* breakpoint_white;
  char* breakpoint_black;
  char* target_code_dump;
} redqueen_workdir_t;

extern redqueen_workdir_t redqueen_workdir;

void setup_redqueen_workdir(char* workdir);

redqueen_t* new_rq_state(CPUState *cpu, page_cache_t* page_cache);
void destroy_rq_state(redqueen_t* self);

void set_rq_instruction(redqueen_t* self, uint64_t addr);
void set_rq_blacklist(redqueen_t* self, uint64_t addr);

void handle_hook(redqueen_t* self);
void handel_se_hook(redqueen_t* self);

void enable_rq_intercept_mode(redqueen_t* self);
void disable_rq_intercept_mode(redqueen_t* self);


void set_se_instruction(redqueen_t* self, uint64_t addr);

void dump_se_registers(redqueen_t* self);
void dump_se_memory_access(redqueen_t* self, cs_insn* insn);
void dump_se_return_access(redqueen_t* self, cs_insn* insn);
void dump_se_memory_access_at(redqueen_t* self, uint64_t instr_addr, uint64_t mem_addr);

void redqueen_insert_hooks(redqueen_t* self);
void redqueen_remove_hooks(redqueen_t* self);

void redqueen_callback(void* opaque, disassembler_mode_t mode, uint64_t start_addr, uint64_t end_addr);

#endif
