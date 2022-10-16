#pragma once


#include <stdint.h>
#include <sys/types.h>

#include "qemu/osdep.h"
#include "block/block.h"

#include "nyx/khash.h"
#include "nyx/redqueen_trace.h"

// #define DEBUG_COW_LAYER

/* Minimum size of CoW buffer that stores data written to
 * the block device between boot time and root snapshot (3GB)
 */
#define COW_CACHE_PRIMARY_MINIMUM_SIZE 0xC0000000

/* Size of CoW buffer which stores data written to
 * the block device between the root snapshot and the
 * next snapshot restore (3GB). This buffer is allocated
 * twice to store the incremental snapshot delta.
 */
#define COW_CACHE_SECONDARY_SIZE 0xC0000000


KHASH_MAP_INIT_INT64(COW_CACHE, uint64_t)

typedef struct cow_cache_s {
    khash_t(COW_CACHE) * lookup_primary;
    khash_t(COW_CACHE) * lookup_secondary;
    khash_t(COW_CACHE) * lookup_secondary_tmp;

    void *data_primary;
    void *data_secondary;
    void *data_secondary_tmp;

    uint64_t cow_primary_size;

    char    *filename;
    uint64_t offset_primary;
    uint64_t offset_secondary;
    uint64_t offset_secondary_tmp;

    bool enabled;
    bool enabled_fuzz;
    bool enabled_fuzz_tmp;

#ifdef DEBUG_COW_LAYER
    uint64_t read_calls;
    uint64_t write_calls;
    uint64_t read_calls_tmp;
    uint64_t write_calls_tmp;
#endif
} cow_cache_t;

cow_cache_t *cow_cache_new(const char *filename);
void         cow_cache_reset(cow_cache_t *self);

void switch_to_fuzz_mode(cow_cache_t *self);

void read_primary_buffer(cow_cache_t *self,
                         const char  *filename_prefix,
                         bool         switch_mode);
void dump_primary_buffer(cow_cache_t *self, const char *filename_prefix);

void cow_cache_read_entry(void *opaque);
void cow_cache_write_entry(void *opaque);

void cow_cache_enable(cow_cache_t *self);
void cow_cache_disable(cow_cache_t *self);

void cow_cache_enable_tmp_mode(cow_cache_t *self);
void cow_cache_disable_tmp_mode(cow_cache_t *self);

void set_global_cow_cache_primary_size(uint64_t new_size);
