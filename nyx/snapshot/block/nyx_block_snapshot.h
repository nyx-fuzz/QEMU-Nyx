#pragma once 

#include <stdint.h>
#include "nyx/snapshot/block/block_cow.h"

typedef struct nyx_block_s{
  cow_cache_t **cow_cache_array;
	uint32_t cow_cache_array_size;

} nyx_block_t; 

nyx_block_t* nyx_block_snapshot_init_from_file(const char* folder, bool pre_snapshot);
nyx_block_t* nyx_block_snapshot_init(void);
void nyx_block_snapshot_switch_to_incremental(nyx_block_t*);

void nyx_block_snapshot_flush(nyx_block_t* self);
void nyx_block_snapshot_switch_incremental(nyx_block_t* self);
void nyx_block_snapshot_disable_incremental(nyx_block_t* self);
void nyx_block_snapshot_reset(nyx_block_t* self);

void nyx_block_snapshot_serialize(nyx_block_t* self, const char* snapshot_folder);