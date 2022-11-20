#include "qemu/osdep.h"
#include "nyx/page_cache.h"
#include "nyx/debug.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/helpers.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include <assert.h>
#include <capstone/capstone.h>
#include <capstone/x86.h>
#include <errno.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>


#define PAGE_CACHE_ADDR_LINE_SIZE sizeof(uint64_t)

#define UNMAPPED_PAGE 0xFFFFFFFFFFFFFFFFULL

static bool reload_addresses(page_cache_t *self)
{
    khiter_t k;
    int      ret;
    uint64_t addr, offset;
    uint64_t value = 0;

    size_t self_offset = lseek(self->fd_address_file, 0, SEEK_END);

    if (self_offset != self->num_pages * PAGE_CACHE_ADDR_LINE_SIZE) {
        /* reload page cache from disk */
        lseek(self->fd_address_file, self->num_pages * PAGE_CACHE_ADDR_LINE_SIZE,
              SEEK_SET);
        offset = self->num_pages;
        while (read(self->fd_address_file, &value, PAGE_CACHE_ADDR_LINE_SIZE)) {
            addr = value & 0xFFFFFFFFFFFFF000ULL;
            offset++;

            /* put new addresses and offsets into the hash map */
            k = kh_get(PC_CACHE, self->lookup, addr);
            if (k == kh_end(self->lookup)) {
                if (value & 0xFFF) {
                    nyx_warn("Load page: %lx (UNMAPPED)\n", addr);
                } else {
                    k = kh_put(PC_CACHE, self->lookup, addr, &ret);
                    kh_value(self->lookup, k) = (offset - 1) * PAGE_SIZE;
                }
            } else {
                /* likely a bug / race condition in page_cache itself! */
                nyx_warn("----> Page duplicate found ...skipping! %lx\n", addr);
                // abort();
            }
        }

        /* reload page dump file */
        munmap(self->page_data, self->num_pages * PAGE_SIZE);
        self->num_pages = self_offset / PAGE_CACHE_ADDR_LINE_SIZE;
        self->page_data = mmap(NULL, (self->num_pages) * PAGE_SIZE,
                               PROT_READ | PROT_WRITE, MAP_SHARED,
                               self->fd_page_file, 0);

        return true;
    }

    return false;
}

static bool append_page(page_cache_t *self, uint64_t page, uint64_t cr3)
{
    bool success = true;
    if (!self->num_pages) {
        assert(!ftruncate(self->fd_page_file, (self->num_pages + 1) * PAGE_SIZE));
        self->page_data = mmap(NULL, (self->num_pages + 1) * PAGE_SIZE,
                               PROT_READ | PROT_WRITE, MAP_SHARED,
                               self->fd_page_file, 0);
    } else {
        munmap(self->page_data, self->num_pages * PAGE_SIZE);
        assert(!ftruncate(self->fd_page_file, (self->num_pages + 1) * PAGE_SIZE));
        self->page_data = mmap(NULL, (self->num_pages + 1) * PAGE_SIZE,
                               PROT_READ | PROT_WRITE, MAP_SHARED,
                               self->fd_page_file, 0);
    }

    if (!dump_page_cr3_ht(page, self->page_data + (PAGE_SIZE * self->num_pages),
                          self->cpu, GET_GLOBAL_STATE()->pt_c3_filter))
    {
        if (!dump_page_cr3_ht(page, self->page_data + (PAGE_SIZE * self->num_pages),
                              self->cpu, GET_GLOBAL_STATE()->parent_cr3))
        {
            if (!dump_page_cr3_snapshot(page,
                                        self->page_data + (PAGE_SIZE * self->num_pages),
                                        self->cpu, GET_GLOBAL_STATE()->parent_cr3))
            {
                munmap(self->page_data, (self->num_pages + 1) * PAGE_SIZE);
                assert(!ftruncate(self->fd_page_file, (self->num_pages) * PAGE_SIZE));
                self->page_data = mmap(NULL, (self->num_pages) * PAGE_SIZE,
                                       PROT_READ | PROT_WRITE, MAP_SHARED,
                                       self->fd_page_file, 0);

                success = false;
                return success;
            }
        }
    }
    fsync(self->fd_page_file);
    self->num_pages++;
    return success;
}

static void page_cache_lock(page_cache_t *self)
{
    int ret = 0;
    while (true) {
        ret = flock(self->fd_lock, LOCK_EX);
        if (ret == 0) {
            return;
        } else if (ret == EINTR) {
            /* try again if acquiring this lock has failed */
            nyx_debug("%s: interrupted by signal...\n", __func__);
        } else {
            assert(false);
        }
    }
}

static void page_cache_unlock(page_cache_t *self)
{
    int ret = 0;
    while (true) {
        ret = flock(self->fd_lock, LOCK_UN);
        if (ret == 0) {
            return;
        } else if (ret == EINTR) {
            /* try again if releasing this lock has failed */
            nyx_debug("%s: interrupted by signal...\n", __func__);
        } else {
            assert(false);
        }
    }
}

static bool update_page_cache(page_cache_t *self, uint64_t page, khiter_t *k)
{
    page_cache_lock(self);

    if (reload_addresses(self)) {
        *k = kh_get(PC_CACHE, self->lookup, page);
    }

    if (*k == kh_end(self->lookup)) {
        int ret;

        uint64_t cr3 = GET_GLOBAL_STATE()->parent_cr3;
        if (!is_addr_mapped_cr3_snapshot(page, self->cpu,
                                         GET_GLOBAL_STATE()->parent_cr3) &&
            !is_addr_mapped_cr3_snapshot(page, self->cpu,
                                         GET_GLOBAL_STATE()->pt_c3_filter))
        {
            /* TODO! */
        }

        *k = kh_get(PC_CACHE, self->lookup, page);
        if (*k == kh_end(self->lookup) && reload_addresses(self)) {
            /* reload sucessful */
            *k = kh_get(PC_CACHE, self->lookup, page);
        } else {
            if (append_page(self, page, cr3)) {
                *k = kh_put(PC_CACHE, self->lookup, page, &ret);
                assert(write(self->fd_address_file, &page,
                             PAGE_CACHE_ADDR_LINE_SIZE) == PAGE_CACHE_ADDR_LINE_SIZE);
                kh_value(self->lookup, *k) = (self->num_pages - 1) * PAGE_SIZE;
            } else {
                page_cache_unlock(self);
                return false;
            }

            *k = kh_get(PC_CACHE, self->lookup, page);
        }
    }
    page_cache_unlock(self);
    return true;
}

uint64_t page_cache_fetch(page_cache_t *self, uint64_t page, bool *success, bool test_mode)
{
    page &= 0xFFFFFFFFFFFFF000ULL;

    if (self->last_page == page) {
        *success = true;
        return self->last_addr;
    }

    khiter_t k;
    k = kh_get(PC_CACHE, self->lookup, page);
    if (k == kh_end(self->lookup)) {
        if (test_mode || update_page_cache(self, page, &k) == false) {
            *success = false;
            return 0;
        }
    }

    self->last_page = page;

    if (kh_value(self->lookup, k) == UNMAPPED_PAGE) {
        self->last_addr = UNMAPPED_PAGE;
    } else {
        self->last_addr = (uint64_t)self->page_data + kh_value(self->lookup, k);
    }

    *success = true;
    return self->last_addr;
}

/* FIXME */
uint64_t page_cache_fetch2(page_cache_t *self, uint64_t page, bool *success)
{
    return page_cache_fetch(self, page, success, false);
}

page_cache_t *page_cache_new(CPUState *cpu, const char *cache_file)
{
    page_cache_t *self = malloc(sizeof(page_cache_t));

    char *tmp1;
    char *tmp2;
    char *tmp3;
    assert(asprintf(&tmp1, "%s.dump", cache_file) != -1);
    assert(asprintf(&tmp2, "%s.addr", cache_file) != -1);
    assert(asprintf(&tmp3, "%s.lock", cache_file) != -1);

    self->lookup          = kh_init(PC_CACHE);
    self->fd_page_file    = open(tmp1, O_CLOEXEC | O_RDWR, S_IRWXU);
    self->fd_address_file = open(tmp2, O_CLOEXEC | O_RDWR, S_IRWXU);

    self->cpu     = cpu;
    self->fd_lock = open(tmp3, O_CLOEXEC);
    assert(self->fd_lock > 0);

    memset(self->disassemble_cache, 0x0, 16);

    self->page_data = NULL;
    self->num_pages = 0;

    self->last_page = 0xFFFFFFFFFFFFFFFF;
    self->last_addr = 0xFFFFFFFFFFFFFFFF;

    nyx_debug_p(PAGE_CACHE_PREFIX, "%s (%s - %s)\n", __func__, tmp1, tmp2);

    free(tmp3);
    free(tmp2);
    free(tmp1);

    if (cs_open(CS_ARCH_X86, CS_MODE_16, &self->handle_16) != CS_ERR_OK)
        assert(false);

    if (cs_open(CS_ARCH_X86, CS_MODE_32, &self->handle_32) != CS_ERR_OK)
        assert(false);

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &self->handle_64) != CS_ERR_OK)
        assert(false);

    cs_option(self->handle_16, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(self->handle_32, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(self->handle_64, CS_OPT_DETAIL, CS_OPT_ON);

    return self;
}

bool page_cache_disassemble(page_cache_t *self, uint64_t address, cs_insn **insn)
{
    return true;
}

cs_insn *page_cache_cs_malloc(page_cache_t *self, disassembler_mode_t mode)
{
    switch (mode) {
    case mode_16:
        return cs_malloc(self->handle_16);
    case mode_32:
        return cs_malloc(self->handle_32);
    case mode_64:
        return cs_malloc(self->handle_64);
    default:
        assert(false);
    }
    return NULL;
}

bool page_cache_disassemble_iter(page_cache_t       *self,
                                 uint64_t           *address,
                                 cs_insn            *insn,
                                 uint64_t           *failed_page,
                                 disassembler_mode_t mode)
{
    *failed_page = 0xFFFFFFFFFFFFFFFFULL;

    bool   success   = true;
    size_t code_size = 16;

    uint8_t *code     = (uint8_t *)page_cache_fetch(self, *address, &success, false);
    uint8_t *code_ptr = 0;


    csh *current_handle = NULL;

    switch (mode) {
    case mode_16:
        current_handle = &self->handle_16;
        break;
    case mode_32:
        current_handle = &self->handle_32;
        break;
    case mode_64:
        current_handle = &self->handle_64;
        break;
    default:
        assert(false);
    }

    if (code == (void *)UNMAPPED_PAGE || success == false) {
        *failed_page = *address;
        return false;
    }

    if ((*address & 0xFFF) >= (0x1000 - 16)) {
        memcpy((void *)self->disassemble_cache,
               (void *)((uint64_t)code + (0x1000 - 16)), 16);
        code_ptr = self->disassemble_cache + 0xf - (0xfff - (*address & 0xfff));
        code = (uint8_t *)page_cache_fetch(self, *address + 0x1000, &success, false);

        if (success == true) {
            memcpy((void *)(self->disassemble_cache + 16), (void *)code, 16);
            return cs_disasm_iter(*current_handle, (const uint8_t **)&code_ptr,
                                  &code_size, address, insn);
        } else {
            code_size = (0xfff - (*address & 0xfff));
            if (!cs_disasm_iter(*current_handle, (const uint8_t **)&code_ptr,
                                &code_size, address, insn))
            {
                *failed_page = (*address + 0x1000) & 0xFFFFFFFFFFFFF000ULL;
                return false;
            }
            return true;
        }
    } else {
        code_ptr = code + (*address & 0xFFF);
        return cs_disasm_iter(*current_handle, (const uint8_t **)&code_ptr,
                              &code_size, address, insn);
    }
}
