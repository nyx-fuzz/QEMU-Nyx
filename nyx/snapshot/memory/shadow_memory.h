#pragma once

#include "nyx/snapshot/devices/state_reallocation.h"
#include <stdint.h>

/* munmap & mmap incremental snapshot area after RESTORE_RATE restores to avoid high memory pressure */
#define RESTORE_RATE 2000

typedef struct ram_region_s {
    /* simple numeric identifier
     *  (can be the same for multiple regions if the memory is
     *	actually splitted across different bases in the guest's memory
     *	but related to the same mapping)
     */
    uint8_t ram_region;

    /* base in the guest's physical address space */
    uint64_t base;

    /* size of this region */
    uint64_t size;

    /* mmap offset of this region (does not apply to the actual guest's memory) */
    uint64_t offset;

    /* pointer to the actual mmap region used by KVM */
    void *host_region_ptr;

    /* pointer to the snapshot mmap + offset */
    void *snapshot_region_ptr;

    /* pointer to the incremental CoW mmap + offset */
    void *incremental_region_ptr;

    char *idstr;

} ram_region_t;


typedef struct shadow_memory_s {
    /* snapshot memory backup */
    void *snapshot_ptr;

    /* snapshot memory backup memfd */
    int snapshot_ptr_fd;

    /* incremental memory backup */
    void *incremental_ptr;

    // fast_reload_tmp_snapshot_t tmp_snapshot;

    /* total memory size */
    uint64_t memory_size;

    /* keep this */
    ram_region_t ram_regions[10];
    uint8_t      ram_regions_num;

    /* additional dirty stack to restore root snapshot */
    uint64_t  root_track_pages_num;
    uint64_t  root_track_pages_size;
    uint64_t *root_track_pages_stack;

    bool incremental_enabled;
} shadow_memory_t;

shadow_memory_t *shadow_memory_init(void);
shadow_memory_t *shadow_memory_init_from_snapshot(const char *snapshot_folder,
                                                  bool        pre_snapshot);

void shadow_memory_prepare_incremental(shadow_memory_t *self);
void shadow_memory_switch_snapshot(shadow_memory_t *self, bool incremental);

void shadow_memory_restore_memory(shadow_memory_t *self);

static inline void shadow_memory_track_dirty_root_pages(shadow_memory_t *self,
                                                        uint64_t         address,
                                                        uint8_t          slot)
{
    if (unlikely(self->root_track_pages_num >= self->root_track_pages_size)) {
        self->root_track_pages_size <<= 2;
        self->root_track_pages_stack =
            realloc(self->root_track_pages_stack,
                    self->root_track_pages_size * sizeof(uint64_t));
    }

    self->root_track_pages_stack[self->root_track_pages_num] =
        (address & 0xFFFFFFFFFFFFF000) | slot;
    self->root_track_pages_num++;
}

bool shadow_memory_is_root_page_tracked(shadow_memory_t *self,
                                        uint64_t         address,
                                        uint8_t          slot);

void shadow_memory_serialize(shadow_memory_t *self, const char *snapshot_folder);

bool shadow_memory_read_physical_memory(shadow_memory_t *self,
                                        uint64_t         address,
                                        void            *ptr,
                                        size_t           size);
