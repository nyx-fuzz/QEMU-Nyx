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
#include "qemu/osdep.h"

#include "exec/gdbstub.h"
#include <errno.h>

#include "exec/ram_addr.h"
#include "qemu/rcu_queue.h"
#include "sysemu/sysemu.h"
#include "cpu.h"

#include "debug.h"
#include "memory_access.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/helpers.h"
#include "nyx/hypercall/hypercall.h"
#include "nyx/state/state.h"
#include "nyx/mem_split.h"

#define INVALID_ADDRESS 0xFFFFFFFFFFFFFFFFULL

static uint64_t get_48_paging_phys_addr(uint64_t cr3,
                                        uint64_t addr,
                                        bool     read_from_snapshot);

#define x86_64_PAGE_SIZE 0x1000
#define x86_64_PAGE_MASK ~(x86_64_PAGE_SIZE - 1)

mem_mode_t get_current_mem_mode(CPUState *cpu)
{
    kvm_arch_get_registers(cpu);

    X86CPU      *cpux86 = X86_CPU(cpu);
    CPUX86State *env    = &cpux86->env;

    if (!(env->cr[0] & CR0_PG_MASK)) {
        return mm_32_protected;
    } else {
        if (env->cr[4] & CR4_PAE_MASK) {
            if (env->hflags & HF_LMA_MASK) {
                if (env->cr[4] & CR4_LA57_MASK) {
                    return mm_64_l5_paging;
                } else {
                    return mm_64_l4_paging;
                }
            } else {
                return mm_32_pae;
            }
        } else {
            return mm_32_paging;
        }
    }

    return mm_unkown;
}

static void set_mem_mode(CPUState *cpu)
{
    GET_GLOBAL_STATE()->mem_mode = get_current_mem_mode(cpu);
}

/*  Warning: This might break memory handling for hypervisor fuzzing => FIXME LATER */
uint64_t get_paging_phys_addr(CPUState *cpu, uint64_t cr3, uint64_t addr)
{
    if (GET_GLOBAL_STATE()->mem_mode == mm_unkown) {
        set_mem_mode(cpu);
    }

    switch (GET_GLOBAL_STATE()->mem_mode) {
    case mm_32_protected:
        return addr & 0xFFFFFFFFULL;
    case mm_32_paging:
        nyx_abort("mem_mode: mm_32_paging not implemented!\n");
    case mm_32_pae:
        nyx_abort("mem_mode: mm_32_pae not implemented!\n");
    case mm_64_l4_paging:
        return get_48_paging_phys_addr(cr3, addr, false);
    case mm_64_l5_paging:
        nyx_abort("mem_mode: mm_64_l5_paging not implemented!\n");
    case mm_unkown:
        nyx_abort("mem_mode: unkown!\n");
    }
    return 0;
}

// FIXME: seems like a duplicate of get_paging_phys_addr()?
static uint64_t get_paging_phys_addr_snapshot(CPUState *cpu, uint64_t cr3, uint64_t addr)
{
    if (GET_GLOBAL_STATE()->mem_mode == mm_unkown) {
        set_mem_mode(cpu);
    }

    switch (GET_GLOBAL_STATE()->mem_mode) {
    case mm_32_protected:
        return addr & 0xFFFFFFFFULL;
    case mm_32_paging:
        nyx_abort("mem_mode: mm_32_paging not implemented!\n");
    case mm_32_pae:
        nyx_abort("mem_mode: mm_32_pae not implemented!\n");
    case mm_64_l4_paging:
        return get_48_paging_phys_addr(cr3, addr, true);
    case mm_64_l5_paging:
        nyx_abort("mem_mode: mm_64_l5_paging not implemented!\n");
    case mm_unkown:
        nyx_abort("mem_mode: unkown!\n");
    }
    return 0;
}

bool read_physical_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu)
{
    kvm_arch_get_registers(cpu);
    cpu_physical_memory_read(address, data, size);
    return true;
}

bool write_physical_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu)
{
    kvm_arch_get_registers(cpu);
    cpu_physical_memory_write(address, data, size);
    return true;
}

static void refresh_kvm(CPUState *cpu)
{
    if (!cpu->vcpu_dirty) {
        kvm_arch_get_registers(cpu);
    }
}

static void refresh_kvm_non_dirty(CPUState *cpu)
{
    if (!cpu->vcpu_dirty) {
        kvm_arch_get_registers_fast(cpu);
    }
}

bool remap_payload_slot(uint64_t phys_addr, uint32_t slot, CPUState *cpu)
{
    assert(GET_GLOBAL_STATE()->shared_payload_buffer_fd &&
           GET_GLOBAL_STATE()->shared_payload_buffer_size);
    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    uint32_t i                    = slot;
    uint64_t phys_addr_ram_offset = address_to_ram_offset(phys_addr);

    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        if (!memcmp(block->idstr, "pc.ram", 6)) {
            /* TODO: put assert calls here */
            munmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset),
                   x86_64_PAGE_SIZE);
            mmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset), 0x1000,
                 PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                 GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i * x86_64_PAGE_SIZE));

            fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
            break;
        }
    }

    return true;
}

bool remap_slot(uint64_t  addr,
                uint32_t  slot,
                CPUState *cpu,
                int       fd,
                uint64_t  shm_size,
                bool virtual,
                uint64_t cr3)
{
    assert(fd && shm_size);
    assert((slot * x86_64_PAGE_SIZE) < shm_size);

    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    uint32_t i = slot;

    uint64_t phys_addr = addr;
    if (virtual) {
        phys_addr = get_paging_phys_addr(cpu, cr3, (addr & x86_64_PAGE_MASK));

        if (phys_addr == INVALID_ADDRESS) {
            nyx_error("Failed to translate v_addr (0x%lx) to p_addr!\n"
                      "Check if the buffer is present in the guest's memory...\n",
                      addr);
            exit(1);
        }
    }
    uint64_t phys_addr_ram_offset = address_to_ram_offset(phys_addr);

    nyx_debug("%s: addr => %lx phys_addr => %lx\n", __func__, addr, phys_addr);

    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        if (!memcmp(block->idstr, "pc.ram", 6)) {
            /* TODO: put assert calls here */
            if (munmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset),
                       x86_64_PAGE_SIZE) == -1)
            {
                nyx_error("%s: munmap failed!\n", __func__);
                assert(false);
            }
            if (mmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset),
                     0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, fd,
                     (i * x86_64_PAGE_SIZE)) == MAP_FAILED)
            {
                nyx_error("%s: mmap failed!\n", __func__);
                assert(false);
            }

            fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
            break;
        }
    }

    return true;
}

bool remap_payload_slot_protected(uint64_t phys_addr, uint32_t slot, CPUState *cpu)
{
    assert(GET_GLOBAL_STATE()->shared_payload_buffer_fd &&
           GET_GLOBAL_STATE()->shared_payload_buffer_size);
    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    uint32_t i = slot;

    uint64_t phys_addr_ram_offset = address_to_ram_offset(phys_addr);

    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        if (!memcmp(block->idstr, "pc.ram", 6)) {
            /* TODO: put assert calls here */
            munmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset),
                   x86_64_PAGE_SIZE);
            mmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset), 0x1000,
                 PROT_READ, MAP_SHARED | MAP_FIXED,
                 GET_GLOBAL_STATE()->shared_payload_buffer_fd, (i * x86_64_PAGE_SIZE));

            fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
            break;
        }
    }

    return true;
}

void resize_shared_memory(uint32_t new_size, uint32_t *shm_size, void **shm_ptr, int fd)
{
    assert(fd && *shm_size);

    /* check if the new_size is a multiple of PAGE_SIZE */
    if (new_size & (PAGE_SIZE - 1)) {
        new_size = (new_size & ~(PAGE_SIZE - 1)) + PAGE_SIZE;
    }

    if (*shm_size >= new_size) {
        /* no need no resize the buffer -> early exit */
        return;
    }

    assert(!GET_GLOBAL_STATE()->in_fuzzing_mode);
    assert(ftruncate(fd, new_size) == 0);

    if (shm_ptr) {
        munmap(*shm_ptr, *shm_size);
        *shm_ptr =
            (void *)mmap(0, new_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        assert(*shm_ptr != MAP_FAILED);
    }

    *shm_size = new_size;
}

bool remap_payload_buffer(uint64_t virt_guest_addr, CPUState *cpu)
{
    assert(GET_GLOBAL_STATE()->shared_payload_buffer_fd &&
           GET_GLOBAL_STATE()->shared_payload_buffer_size);
    assert(GET_GLOBAL_STATE()->shared_payload_buffer_size % x86_64_PAGE_SIZE == 0);
    RAMBlock *block;
    refresh_kvm_non_dirty(cpu);

    for (uint32_t i = 0;
         i < (GET_GLOBAL_STATE()->shared_payload_buffer_size / x86_64_PAGE_SIZE); i++)
    {
        uint64_t phys_addr =
            get_paging_phys_addr(cpu, GET_GLOBAL_STATE()->parent_cr3,
                                 ((virt_guest_addr + (i * x86_64_PAGE_SIZE)) &
                                  x86_64_PAGE_MASK));

        assert(phys_addr != INVALID_ADDRESS);

        uint64_t phys_addr_ram_offset = address_to_ram_offset(phys_addr);

        QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
            if (!memcmp(block->idstr, "pc.ram", 6)) {
                if (munmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset),
                           x86_64_PAGE_SIZE) == -1)
                {
                    nyx_error("munmap failed!\n");
                    assert(false);
                }
                if (mmap((void *)(((uint64_t)block->host) + phys_addr_ram_offset),
                         0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED,
                         GET_GLOBAL_STATE()->shared_payload_buffer_fd,
                         (i * x86_64_PAGE_SIZE)) == MAP_FAILED)
                {
                    nyx_error("mmap failed!\n");
                    assert(false);
                }

                memset((block->host) + phys_addr_ram_offset, 0xab, 0x1000);

                if (GET_GLOBAL_STATE()->protect_payload_buffer) {
                    mprotect((block->host) + phys_addr_ram_offset, 0x1000, PROT_READ);
                }

                fast_reload_blacklist_page(get_fast_reload_snapshot(), phys_addr);
                break;
            }
        }
    }
    return true;
}

bool write_virtual_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu)
{
    /* TODO: later &address_space_memory + phys_addr -> mmap SHARED */
    int         asidx;
    MemTxAttrs  attrs;
    hwaddr      phys_addr;
    MemTxResult res;

    uint64_t counter, l, i;

    counter = size;
    while (counter != 0) {
        l = x86_64_PAGE_SIZE;
        if (l > counter)
            l = counter;

        refresh_kvm(cpu);
        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
        attrs = MEMTXATTRS_UNSPECIFIED;
        phys_addr =
            cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);

        if (phys_addr == INVALID_ADDRESS) {
            nyx_debug_p(MEM_PREFIX, "phys_addr == -1:\t%lx\n", address);
            return false;
        }

        phys_addr += (address & ~x86_64_PAGE_MASK);
        res = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr,
                               MEMTXATTRS_UNSPECIFIED, data, l, true);
        if (res != MEMTX_OK) {
            nyx_debug_p(MEM_PREFIX, "!MEMTX_OK:\t%lx\n", address);
            return false;
        }

        i++;
        data += l;
        address += l;
        counter -= l;
    }

    return true;
}


void hexdump_virtual_memory(uint64_t address, uint32_t size, CPUState *cpu)
{
    assert(size < 0x100000); // 1MB max
    uint64_t i = 0;
    uint8_t  tmp[17];
    uint8_t *data    = malloc(size);
    bool     success = read_virtual_memory(address, data, size, cpu);

    if (success) {
        for (i = 0; i < size; i++) {
            if (!(i % 16)) {
                if (i != 0) {
                    printf("  %s\n", tmp);
                }
                printf("  %04lx ", i);
            }
            printf(" %02x", data[i]);

            if ((data[i] < 0x20) || (data[i] > 0x7e))
                tmp[i % 16] = '.';
            else
                tmp[i % 16] = data[i];
            tmp[(i % 16) + 1] = '\0';
        }

        while ((i % 16) != 0) {
            printf("   ");
            i++;
        }
        printf("  %s\n", tmp);
    }

    free(data);
}


static int redqueen_insert_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    static const uint8_t int3 = 0xcc;

    hwaddr phys_addr =
        (hwaddr)get_paging_phys_addr(cs, GET_GLOBAL_STATE()->parent_cr3, bp->pc);
    int asidx = cpu_asidx_from_attrs(cs, MEMTXATTRS_UNSPECIFIED);

    if (address_space_rw(cpu_get_address_space(cs, asidx), phys_addr,
                         MEMTXATTRS_UNSPECIFIED, (uint8_t *)&bp->saved_insn, 1, 0) ||
        address_space_rw(cpu_get_address_space(cs, asidx), phys_addr,
                         MEMTXATTRS_UNSPECIFIED, (uint8_t *)&int3, 1, 1))
    {
        // nyx_debug("%s WRITE AT %lx %lx failed!\n", __func__, bp->pc, phys_addr);
        return -EINVAL;
    }

    return 0;
}

static int redqueen_remove_sw_breakpoint(CPUState *cs, struct kvm_sw_breakpoint *bp)
{
    uint8_t int3;

    hwaddr phys_addr =
        (hwaddr)get_paging_phys_addr(cs, GET_GLOBAL_STATE()->parent_cr3, bp->pc);
    int asidx = cpu_asidx_from_attrs(cs, MEMTXATTRS_UNSPECIFIED);

    if (address_space_rw(cpu_get_address_space(cs, asidx), phys_addr,
                         MEMTXATTRS_UNSPECIFIED, (uint8_t *)&int3, 1, 0) ||
        int3 != 0xcc ||
        address_space_rw(cpu_get_address_space(cs, asidx), phys_addr,
                         MEMTXATTRS_UNSPECIFIED, (uint8_t *)&bp->saved_insn, 1, 1))
    {
        // nyx_debug("%s failed\n", __func__);
        return -EINVAL;
    }

    return 0;
}

static struct kvm_sw_breakpoint *redqueen_find_breakpoint(CPUState    *cpu,
                                                          target_ulong pc)
{
    struct kvm_sw_breakpoint *bp;

    QTAILQ_FOREACH (bp, &GET_GLOBAL_STATE()->redqueen_breakpoints, entry) {
        if (bp->pc == pc) {
            return bp;
        }
    }
    return NULL;
}

static int redqueen_breakpoints_active(CPUState *cpu)
{
    return !QTAILQ_EMPTY(&GET_GLOBAL_STATE()->redqueen_breakpoints);
}

struct kvm_set_guest_debug_data {
    struct kvm_guest_debug dbg;
    int                    err;
};

static int redqueen_update_guest_debug(CPUState *cpu)
{
    struct kvm_set_guest_debug_data data;

    data.dbg.control = 0;

    if (redqueen_breakpoints_active(cpu)) {
        data.dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
    }

    return kvm_vcpu_ioctl(cpu, KVM_SET_GUEST_DEBUG, &data.dbg);
}

static void redqueen_remove_all_breakpoints(CPUState *cpu)
{
    struct kvm_sw_breakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE (bp, &GET_GLOBAL_STATE()->redqueen_breakpoints, entry, next) {
        redqueen_remove_sw_breakpoint(cpu, bp);
        QTAILQ_REMOVE(&GET_GLOBAL_STATE()->redqueen_breakpoints, bp, entry);
        g_free(bp);
    }

    redqueen_update_guest_debug(cpu);
}

static int redqueen_insert_breakpoint(CPUState *cpu, target_ulong addr, target_ulong len)
{
    struct kvm_sw_breakpoint *bp;
    int                       err;

    bp = redqueen_find_breakpoint(cpu, addr);
    if (bp) {
        bp->use_count++;
        return 0;
    }

    bp            = g_malloc(sizeof(struct kvm_sw_breakpoint));
    bp->pc        = addr;
    bp->use_count = 1;

    err = redqueen_insert_sw_breakpoint(cpu, bp);
    if (err) {
        g_free(bp);
        return err;
    }

    QTAILQ_INSERT_HEAD(&GET_GLOBAL_STATE()->redqueen_breakpoints, bp, entry);

    err = redqueen_update_guest_debug(cpu);
    if (err) {
        return err;
    }

    return 0;
}

static int redqueen_remove_breakpoint(CPUState *cpu, target_ulong addr, target_ulong len)
{
    struct kvm_sw_breakpoint *bp;
    int                       err;

    bp = redqueen_find_breakpoint(cpu, addr);
    if (!bp) {
        return -ENOENT;
    }

    if (bp->use_count > 1) {
        bp->use_count--;
        return 0;
    }

    err = redqueen_remove_sw_breakpoint(cpu, bp);
    if (err) {
        return err;
    }

    QTAILQ_REMOVE(&GET_GLOBAL_STATE()->redqueen_breakpoints, bp, entry);
    g_free(bp);

    err = redqueen_update_guest_debug(cpu);
    if (err) {
        return err;
    }

    return 0;
}

int insert_breakpoint(CPUState *cpu, uint64_t addr, uint64_t len)
{
    redqueen_insert_breakpoint(cpu, addr, len);
    redqueen_update_guest_debug(cpu);
    return 0;
}


int remove_breakpoint(CPUState *cpu, uint64_t addr, uint64_t len)
{
    redqueen_remove_breakpoint(cpu, addr, len);
    redqueen_update_guest_debug(cpu);
    return 0;
}

void remove_all_breakpoints(CPUState *cpu)
{
    redqueen_remove_all_breakpoints(cpu);
}


#define PENTRIES   0x200
#define PPAGE_SIZE 0x1000

static bool read_memory(uint64_t  address,
                        uint64_t *buffer,
                        size_t    size,
                        bool      read_from_snapshot)
{
    if (unlikely(address == INVALID_ADDRESS)) {
        return false;
    }

    if (unlikely(read_from_snapshot)) {
        return read_snapshot_memory(get_fast_reload_snapshot(), address,
                                    (uint8_t *)buffer, size);
    }

    // NB: This API exposed by exec.h doesn't signal failure, although it can
    // fail. Figure out how to expose the address space object instead and then
    // we can actually check the return value here. Until then, will clear the
    // buffer contents first.
    memset(buffer, 0, size);
    cpu_physical_memory_rw(address, (uint8_t *)buffer, size, false);
    return true;
}

__attribute__((always_inline)) inline static bool bit(uint64_t value, uint8_t lsb)
{
    return (value >> lsb) & 1;
}

__attribute__((always_inline)) inline static uint64_t bits(uint64_t value,
                                                           uint8_t  lsb,
                                                           uint8_t  msb)
{
    return (value & ((0xffffffffffffffffull >> (64 - (msb - lsb + 1))) << lsb)) >> lsb;
}

// Helper function to load an entire pagetable table. These are PENTRIES
// 64-bit entries, so entries must point to a sufficiently large buffer.
static bool load_table(uint64_t address, uint64_t *entries, bool read_from_snapshot)
{
    if (unlikely(!read_memory(address, entries, 512 * sizeof(*entries),
                              read_from_snapshot)))
    {
        return false;
    }

    return true;
}

// Helper function to load a single pagetable entry. We simplify things by
// returning the same invalid value (0) for both non-present entries and
// any other error conditions, since we don't need to handle these cases
// differently.
static uint64_t load_entry(uint64_t address, uint64_t index, bool read_from_snapshot)
{
    uint64_t entry = 0;
    if (unlikely(!read_memory(address + (index * sizeof(entry)), &entry,
                              sizeof(entry), read_from_snapshot)))
    {
        return 0;
    }

    // Check that the entry is present.
    if (unlikely(!bit(entry, 0))) {
        return 0;
    }

    return entry;
}

static void print_page(
    uint64_t address, uint64_t entry, size_t size, bool s, bool w, bool x)
{
    fprintf(stderr, " %c%c%c %016lx %zx", s ? 's' : 'u', w ? 'w' : 'r',
            x ? 'x' : '-', (bits(entry, 12, 51) << 12) & ~(size - 1), size);
}

static void print_48_pte(uint64_t address,
                         uint64_t pde_entry,
                         bool     read_from_snapshot,
                         bool     s,
                         bool     w,
                         bool     x)
{
    uint64_t pte_address = bits(pde_entry, 12, 51) << 12;
    uint64_t pte_table[PENTRIES];

    if (!load_table(pte_address, pte_table, read_from_snapshot)) {
        return;
    }

    for (size_t i = 0; i < PENTRIES; ++i) {
        uint64_t entry = pte_table[i];

        if (entry) {
            fprintf(stderr, "\n   1 %016lx [%ld]", address | i << 12, entry);
        }

        if (!bit(entry, 0)) {
            // Not present.
        } else {
            print_page(address | i << 12, entry, 0x1000, s & !bit(entry, 2),
                       w & bit(entry, 1), x & !bit(entry, 63));
        }
    }
}

static void print_48_pde(uint64_t address,
                         uint64_t pdpte_entry,
                         bool     read_from_snapshot,
                         bool     s,
                         bool     w,
                         bool     x)
{
    uint64_t pde_address = bits(pdpte_entry, 12, 51) << 12;
    uint64_t pde_table[PENTRIES];

    if (!load_table(pde_address, pde_table, read_from_snapshot)) {
        return;
    }

    for (size_t i = 0; i < PENTRIES; ++i) {
        uint64_t entry = pde_table[i];

        if (entry) {
            fprintf(stderr, "\n  2 %016lx [%ld]", address | i << 21, entry);
        }

        if (!bit(entry, 0)) {
            // Not present.
        } else if (bit(entry, 7)) {
            print_page(address | i << 21, entry, 0x200000, s & !bit(entry, 2),
                       w & bit(entry, 1), x & !bit(entry, 63));
        } else {
            print_48_pte(address | i << 21, entry, read_from_snapshot,
                         s & !bit(entry, 2), w & bit(entry, 1), x & !bit(entry, 63));
        }
    }
}

static void print_48_pdpte(uint64_t address,
                           uint64_t pml4_entry,
                           bool     read_from_snapshot,
                           bool     s,
                           bool     w,
                           bool     x)
{
    uint64_t pdpte_address = bits(pml4_entry, 12, 51) << 12;
    uint64_t pdpte_table[PENTRIES];

    if (!load_table(pdpte_address, pdpte_table, read_from_snapshot)) {
        return;
    }

    for (size_t i = 0; i < PENTRIES; ++i) {
        uint64_t entry = pdpte_table[i];

        if (entry) {
            fprintf(stderr, "\n 3 %016lx [%ld]", address | i << 30, entry);
        }

        if (!bit(entry, 0)) {
            // Not present.
        } else if (bit(entry, 7)) {
            print_page(address | i << 30, entry, 0x40000000, s & !bit(entry, 2),
                       w & bit(entry, 1), x & !bit(entry, 63));
        } else {
            print_48_pde(address | i << 30, entry, read_from_snapshot,
                         s & !bit(entry, 2), w & bit(entry, 1), x & !bit(entry, 63));
        }
    }
}

static void print_48_pagetables_(uint64_t cr3, bool read_from_snapshot)
{
    uint64_t pml4_address = bits(cr3, 12, 51) << 12;
    uint64_t pml4_table[PENTRIES];

    if (!load_table(pml4_address, pml4_table, read_from_snapshot)) {
        return;
    }

    for (size_t i = 0; i < PENTRIES; ++i) {
        uint64_t entry   = pml4_table[i];
        uint64_t address = i << 39;
        // Ensure canonical virtual address
        if (bit(address, 47)) {
            address |= 0xffff000000000000ul;
        }

        if (entry) {
            fprintf(stderr, "\n4 %016lx [%ld]", address, entry);
        }

        if (bit(entry, 0)) {
            print_48_pdpte(address, entry, read_from_snapshot, !bit(entry, 2),
                           bit(entry, 1), !bit(entry, 63));
        }
    }
}

void print_48_pagetables(uint64_t cr3)
{
    static bool printed = false;
    if (!printed) {
        fprintf(stderr, "pagetables for cr3 %lx", cr3);
        print_48_pagetables_(cr3, false);
        printed = true;
        fprintf(stderr, "\n");
    }
}

static uint64_t get_48_paging_phys_addr(uint64_t cr3,
                                        uint64_t addr,
                                        bool     read_from_snapshot)
{
    uint64_t pml4_address = bits(cr3, 12, 51) << 12;
    uint64_t pml4_offset  = bits(addr, 39, 47);
    uint64_t pml4_entry = load_entry(pml4_address, pml4_offset, read_from_snapshot);
    if (unlikely(!pml4_entry)) {
        return INVALID_ADDRESS;
    }

    uint64_t pdpte_address = bits(pml4_entry, 12, 51) << 12;
    uint64_t pdpte_offset  = bits(addr, 30, 38);
    uint64_t pdpte_entry = load_entry(pdpte_address, pdpte_offset, read_from_snapshot);
    if (unlikely(!pdpte_entry)) {
        return INVALID_ADDRESS;
    }

    if (unlikely(bit(pdpte_entry, 7))) {
        // 1GByte page translation.
        uint64_t page_address = bits(pdpte_entry, 12, 51) << 12;
        uint64_t page_offset  = bits(addr, 0, 29);
        return page_address + page_offset;
    }

    uint64_t pde_address = bits(pdpte_entry, 12, 51) << 12;
    uint64_t pde_offset  = bits(addr, 21, 29);
    uint64_t pde_entry   = load_entry(pde_address, pde_offset, read_from_snapshot);
    if (unlikely(!pde_entry)) {
        return INVALID_ADDRESS;
    }

    if (unlikely(bit(pde_entry, 7))) {
        // 2MByte page translation.
        uint64_t page_address = bits(pde_entry, 12, 51) << 12;
        uint64_t page_offset  = bits(addr, 0, 20);
        return page_address + page_offset;
    }

    uint64_t pte_address = bits(pde_entry, 12, 51) << 12;
    uint64_t pte_offset  = bits(addr, 12, 20);
    uint64_t pte_entry   = load_entry(pte_address, pte_offset, read_from_snapshot);
    if (unlikely(!pte_entry)) {
        return INVALID_ADDRESS;
    }

    // 4Kbyte page translation.
    uint64_t page_address = bits(pte_entry, 12, 51) << 12;
    uint64_t page_offset  = bits(addr, 0, 11);
    return page_address + page_offset;
}

// #define DEBUG_48BIT_WALK

bool read_virtual_memory(uint64_t address, uint8_t *data, uint32_t size, CPUState *cpu)
{
    uint8_t tmp_buf[x86_64_PAGE_SIZE];
    hwaddr  phys_addr;
    int     asidx;

    uint64_t amount_copied = 0;

    kvm_arch_get_registers_fast(cpu);
    CPUX86State *env = &(X86_CPU(cpu))->env;

    // copy per page
    while (amount_copied < size) {
        uint64_t len_to_copy = (size - amount_copied);
        if (len_to_copy > x86_64_PAGE_SIZE)
            len_to_copy = x86_64_PAGE_SIZE;

        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
#ifdef DEBUG_48BIT_WALK
        phys_addr_2 =
            cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);
#endif
        phys_addr = (hwaddr)get_paging_phys_addr(cpu, env->cr[3], address) &
                    0xFFFFFFFFFFFFF000ULL; // != 0xFFFFFFFFFFFFFFFFULL)

#ifdef DEBUG_48BIT_WALK
        assert(phys_addr == phys_addr_2);
#endif

        if (phys_addr == INVALID_ADDRESS) {
            uint64_t next_page   = (address & x86_64_PAGE_MASK) + x86_64_PAGE_SIZE;
            uint64_t len_skipped = next_page - address;
            if (len_skipped > size - amount_copied) {
                len_skipped = size - amount_copied;
            }

            nyx_warn("Read from unmapped memory addr %lx, skipping to %lx\n",
                     address, next_page);
            memset(data + amount_copied, ' ', len_skipped);
            address += len_skipped;
            amount_copied += len_skipped;
            continue;
        }

        phys_addr += (address & ~x86_64_PAGE_MASK);
        uint64_t remaining_on_page = x86_64_PAGE_SIZE - (address & ~x86_64_PAGE_MASK);
        if (len_to_copy > remaining_on_page) {
            len_to_copy = remaining_on_page;
        }

        MemTxResult txt = address_space_rw(cpu_get_address_space(cpu, asidx),
                                           phys_addr, MEMTXATTRS_UNSPECIFIED,
                                           tmp_buf, len_to_copy, 0);
        if (txt) {
            nyx_debug_p(MEM_PREFIX,
                        "Warning, read failed for virt addr %lx (phys: %lx)\n",
                        address, phys_addr);
        }

        memcpy(data + amount_copied, tmp_buf, len_to_copy);

        address += len_to_copy;
        amount_copied += len_to_copy;
    }

    return true;
}

bool is_addr_mapped_cr3(uint64_t address, CPUState *cpu, uint64_t cr3)
{
    return (get_paging_phys_addr(cpu, cr3, address) != INVALID_ADDRESS);
}

bool is_addr_mapped(uint64_t address, CPUState *cpu)
{
    CPUX86State *env = &(X86_CPU(cpu))->env;
    kvm_arch_get_registers_fast(cpu);
    return (get_paging_phys_addr(cpu, env->cr[3], address) != INVALID_ADDRESS);
}

bool is_addr_mapped_cr3_snapshot(uint64_t address, CPUState *cpu, uint64_t cr3)
{
    return (get_paging_phys_addr_snapshot(cpu, cr3, address) != INVALID_ADDRESS);
}

bool dump_page_cr3_snapshot(uint64_t address, uint8_t *data, CPUState *cpu, uint64_t cr3)
{
    fast_reload_t *snapshot  = get_fast_reload_snapshot();
    uint64_t       phys_addr = get_paging_phys_addr_snapshot(cpu, cr3, address);
    if (phys_addr == INVALID_ADDRESS) {
        return false;
    } else {
        return read_snapshot_memory(snapshot, phys_addr, data, PPAGE_SIZE);
    }
}


bool dump_page_cr3_ht(uint64_t address, uint8_t *data, CPUState *cpu, uint64_t cr3)
{
    hwaddr phys_addr = (hwaddr)get_paging_phys_addr(cpu, cr3, address);
    int    asidx     = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
    if (phys_addr == INVALID_ADDRESS ||
        address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr,
                         MEMTXATTRS_UNSPECIFIED, data, 0x1000, 0))
    {
        if (phys_addr != INVALID_ADDRESS) {
            nyx_warn("%s: Read failed for virt addr %lx (phys: %lx)\n", __func__,
                     address, phys_addr);
        }
        return false;
    }
    return true;
}

bool dump_page_ht(uint64_t address, uint8_t *data, CPUState *cpu)
{
    CPUX86State *env = &(X86_CPU(cpu))->env;
    kvm_arch_get_registers_fast(cpu);
    hwaddr phys_addr = (hwaddr)get_paging_phys_addr(cpu, env->cr[3], address);
    int    asidx     = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
    if (phys_addr == 0xffffffffffffffffULL ||
        address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr,
                         MEMTXATTRS_UNSPECIFIED, data, 0x1000, 0))
    {
        if (phys_addr != 0xffffffffffffffffULL) {
            nyx_warn("%s: Read failed for virt addr %lx (phys: %lx)\n", __func__,
                     address, phys_addr);
        }
    }
    return true;
}

uint64_t disassemble_at_rip(int fd, uint64_t address, CPUState *cpu, uint64_t cr3)
{
    csh handle;

    size_t  code_size = 256;
    uint8_t code_ptr[256];


    /* don't => GET_GLOBAL_STATE()->disassembler_word_width */
    if (cs_open(CS_ARCH_X86,
                get_capstone_mode(GET_GLOBAL_STATE()->disassembler_word_width),
                &handle) != CS_ERR_OK)
        assert(false);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn *insn = cs_malloc(handle);

    read_virtual_memory(address, code_ptr, code_size, cpu);

    int count = cs_disasm(handle, code_ptr, code_size, address, 5, &insn);
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            nyx_error("=> 0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address,
                      insn[i].mnemonic, insn[i].op_str);
        }
    } else {
        nyx_error("nothing to decode at %s(%lx,%lx)\n", __func__, address, cr3);
    }


    cs_free(insn, 1);
    cs_close(&handle);
    return 0;
}
