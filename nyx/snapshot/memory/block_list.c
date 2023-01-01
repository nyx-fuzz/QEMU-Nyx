#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/sysemu.h"

#include "exec/ram_addr.h"
#include "migration/migration.h"
#include "qemu/rcu_queue.h"

#include "nyx/memory_access.h"

#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/block_list.h"
#include "nyx/snapshot/memory/shadow_memory.h"
#include "nyx/mem_split.h"

#define REALLOC_SIZE 0x8000

// #define DEBUG_NYX_SNAPSHOT_PAGE_BLOCKLIST

uint64_t snapshot_page_blocklist_get_phys_area_size(snapshot_page_blocklist_t *self){
    return self->phys_area_size;
}

snapshot_page_blocklist_t *snapshot_page_blocklist_init(void)
{
    snapshot_page_blocklist_t *self = malloc(sizeof(snapshot_page_blocklist_t));

    uint64_t ram_size    = get_ram_size();
    self->phys_area_size = ram_size <= get_mem_split_start() ?
                               ram_size :
                               ram_size + (get_mem_split_end() - get_mem_split_start());

    self->phys_bitmap = malloc(BITMAP_SIZE(self->phys_area_size));
    memset(self->phys_bitmap, 0x0, BITMAP_SIZE(self->phys_area_size));

    if (ram_size > get_mem_split_start()) {
        memset(self->phys_bitmap + BITMAP_SIZE(get_mem_split_start()), 0xff,
               BITMAP_SIZE((get_mem_split_end() - get_mem_split_start())));
    }

    self->pages_num  = 0;
    self->pages_size = REALLOC_SIZE;
    self->pages      = malloc(sizeof(uint64_t) * REALLOC_SIZE);

    return self;
}

void snapshot_page_blocklist_add(snapshot_page_blocklist_t *self, uint64_t phys_addr)
{
    if (phys_addr == -1) {
        nyx_error("%s: phys_addr=%lx\n", __func__, phys_addr);
        return;
    }
    assert(self != NULL);

    assert(phys_addr < self->phys_area_size);

    if (self->pages_num <= self->pages_size) {
        self->pages_size += REALLOC_SIZE;
        self->pages = realloc(self->pages, sizeof(uint64_t) * self->pages_size);
    }

    self->pages[self->pages_num] = phys_addr;
    self->pages_num++;

    /* check if bit is empty */
    assert(test_bit(phys_addr >> 12, (const unsigned long *)self->phys_bitmap) == 0);

    /* set bit for lookup */
    set_bit(phys_addr >> 12, (unsigned long *)self->phys_bitmap);


#ifdef DEBUG_NYX_SNAPSHOT_PAGE_BLOCKLIST
    printf("%s: %lx\n", __func__, phys_addr);
#endif
}
