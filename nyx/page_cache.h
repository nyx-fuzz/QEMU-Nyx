#pragma once

#include "khash.h"
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <libxdc.h>

#include "qemu-common.h"
#include "khash.h"

KHASH_MAP_INIT_INT64(PC_CACHE, uint64_t)

typedef struct page_cache_s {
    CPUState *cpu;
    khash_t(PC_CACHE) * lookup;
    int      fd_page_file;
    int      fd_address_file;
    int      fd_lock;
    uint8_t  disassemble_cache[32];
    void    *page_data;
    uint32_t num_pages;

    csh handle_16;
    csh handle_32;
    csh handle_64;

    uint64_t last_page;
    uint64_t last_addr;
} page_cache_t;

page_cache_t *page_cache_new(CPUState *cpu, const char *cache_file);
uint64_t      page_cache_fetch(page_cache_t *self,
                               uint64_t      page,
                               bool         *success,
                               bool          test_mode);

bool page_cache_disassemble(page_cache_t *self, uint64_t address, cs_insn **insn);
bool page_cache_disassemble_iter(page_cache_t       *self,
                                 uint64_t           *address,
                                 cs_insn            *insn,
                                 uint64_t           *failed_page,
                                 disassembler_mode_t mode);

cs_insn *page_cache_cs_malloc(page_cache_t *self, disassembler_mode_t mode);

uint64_t page_cache_fetch2(page_cache_t *self, uint64_t page, bool *success);