#include "qemu/osdep.h"

#include "block/qapi.h"
#include "migration/vmstate.h"
#include "qemu/main-loop.h"
#include "sysemu/block-backend.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"

#include "nyx/debug.h"
#include "nyx/snapshot/block/nyx_block_snapshot.h"
#include "nyx/state/state.h"

typedef struct fast_reload_cow_entry_s {
    uint32_t id;
    char     idstr[256];
} fast_reload_cow_entry_t;


nyx_block_t *nyx_block_snapshot_init_from_file(const char *folder, bool pre_snapshot)
{
    nyx_block_t *self = malloc(sizeof(nyx_block_t));
    memset(self, 0, sizeof(nyx_block_t));

    BlockBackend           *blk;
    fast_reload_cow_entry_t entry;

    char *tmp1;
    char *tmp2;

    assert(asprintf(&tmp1, "%s/fs_cache.meta", folder) != -1);
    assert(asprintf(&tmp2, "%s/fs_drv", folder) != -1);


    self->cow_cache_array_size = 0;

    FILE *f = fopen(tmp1, "r");
    assert(f != NULL);

    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk && blk->cow_cache) {
            nyx_debug("%p %s\n", blk->cow_cache, blk->cow_cache->filename);
            self->cow_cache_array_size++;
        }
    }

    uint32_t temp_cow_cache_array_size;

    assert(fread(&temp_cow_cache_array_size, sizeof(uint32_t), 1, f) == 1);

    nyx_debug("%d vs %x\n", temp_cow_cache_array_size, self->cow_cache_array_size);
    assert(self->cow_cache_array_size == temp_cow_cache_array_size);

    self->cow_cache_array =
        (cow_cache_t **)malloc(sizeof(cow_cache_t *) * self->cow_cache_array_size);

    uint32_t i  = 0;
    uint32_t id = 0;
    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk && blk->cow_cache) {
            self->cow_cache_array[i++] = blk->cow_cache;
            assert(fread(&entry, sizeof(fast_reload_cow_entry_t), 1, f) == 1);

            assert(!strcmp(entry.idstr, blk->cow_cache->filename));
            assert(entry.id == id);
        }
        id++;
    }


    fclose(f);

    for (i = 0; i < self->cow_cache_array_size; i++) {
        read_primary_buffer(self->cow_cache_array[i], tmp2, !pre_snapshot);
    }

    free(tmp1);
    free(tmp2);
    return self;
}

nyx_block_t *nyx_block_snapshot_init(void)
{
    nyx_block_t *self = malloc(sizeof(nyx_block_t));
    memset(self, 0, sizeof(nyx_block_t));

    BlockBackend *blk;
    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk && blk->cow_cache) {
            nyx_debug("%p %s\n", blk->cow_cache, blk->cow_cache->filename);
            self->cow_cache_array_size++;
        }
    }

    self->cow_cache_array =
        (cow_cache_t **)malloc(sizeof(cow_cache_t *) * self->cow_cache_array_size);

    uint32_t i = 0;
    for (blk = blk_next(NULL); blk; blk = blk_next(blk)) {
        if (blk && blk->cow_cache) {
            self->cow_cache_array[i++] = blk->cow_cache;
        }
    }


    for (i = 0; i < self->cow_cache_array_size; i++) {
        switch_to_fuzz_mode(self->cow_cache_array[i]);
    }
    return self;
}

void nyx_block_snapshot_flush(nyx_block_t *self)
{
    GET_GLOBAL_STATE()->cow_cache_full = false;
}

void nyx_block_snapshot_switch_incremental(nyx_block_t *self)
{
    for (uint32_t i = 0; i < self->cow_cache_array_size; i++) {
        cow_cache_enable_tmp_mode(self->cow_cache_array[i]);
    }
    nyx_block_snapshot_flush(self);
}

void nyx_block_snapshot_disable_incremental(nyx_block_t *self)
{
    for (uint32_t i = 0; i < self->cow_cache_array_size; i++) {
        cow_cache_disable_tmp_mode(self->cow_cache_array[i]);
    }
}

void nyx_block_snapshot_reset(nyx_block_t *self)
{
    for (uint32_t i = 0; i < self->cow_cache_array_size; i++) {
        cow_cache_reset(self->cow_cache_array[i]);
    }
}

void nyx_block_snapshot_serialize(nyx_block_t *self, const char *snapshot_folder)
{
    fast_reload_cow_entry_t entry;

    char *tmp1;
    char *tmp2;

    assert(asprintf(&tmp1, "%s/fs_cache.meta", snapshot_folder) != -1);
    assert(asprintf(&tmp2, "%s/fs_drv", snapshot_folder) != -1);


    FILE *f = fopen(tmp1, "w");

    fwrite(&(self->cow_cache_array_size), sizeof(uint32_t), 1, f);

    for (uint32_t i = 0; i < self->cow_cache_array_size; i++) {
        entry.id = i;
        strncpy((char *)&entry.idstr,
                (const char *)self->cow_cache_array[i]->filename, 255);
        fwrite(&entry, sizeof(fast_reload_cow_entry_t), 1, f);

        dump_primary_buffer(self->cow_cache_array[i], tmp2);
    }
    fclose(f);

    free(tmp1);
    free(tmp2);
}
