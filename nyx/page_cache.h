#pragma once

#include <capstone/capstone.h>
#include <capstone/x86.h>
#ifndef STANDALONE_DECODER
#include "qemu/osdep.h"
#endif
#include "khash.h"
#include <libxdc.h>

KHASH_MAP_INIT_INT64(PC_CACHE, uint64_t)

typedef struct page_cache_s{
#ifndef STANDALONE_DECODER
	CPUState *cpu;
#endif
	khash_t(PC_CACHE) *lookup;
	int fd_page_file;
	int fd_address_file; 
	int fd_lock;
	uint8_t disassemble_cache[32];
	void* page_data;
	uint32_t num_pages;

	csh handle_16;
	csh handle_32;
	csh handle_64;

	uint64_t last_page;
	uint64_t last_addr;  
} page_cache_t;

#ifndef STANDALONE_DECODER
page_cache_t* page_cache_new(CPUState *cpu, const char* cache_file);
#else
page_cache_t* page_cache_new(const char* cache_file, uint8_t disassembler_word_width);
void page_cache_destroy(page_cache_t* self);
bool append_page(page_cache_t* self, uint64_t page, uint8_t* ptr);
#endif

uint64_t page_cache_fetch(page_cache_t* self, uint64_t page, bool* success, bool test_mode);

bool page_cache_disassemble(page_cache_t* self, uint64_t address, cs_insn **insn);
bool page_cache_disassemble_iter(page_cache_t* self, uint64_t* address, cs_insn *insn, uint64_t* failed_page, disassembler_mode_t mode);

cs_insn* page_cache_cs_malloc(page_cache_t* self, disassembler_mode_t mode);


uint64_t page_cache_fetch2(page_cache_t* self, uint64_t page, bool* success);