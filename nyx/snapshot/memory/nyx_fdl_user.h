#pragma once 

#include <stdint.h>
#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/block_list.h"
#include "nyx/snapshot/memory/shadow_memory.h"
#include "nyx/snapshot/memory/backend/nyx_fdl.h"

typedef struct nyx_fdl_user_s{
    struct {
        uint64_t* stack;
        uint8_t* bitmap;
        uint64_t pos;
    }entry[MAX_REGIONS];

    uint8_t num;
    bool enabled;
}nyx_fdl_user_t;

nyx_fdl_user_t* nyx_fdl_user_init(shadow_memory_t* shadow_memory_state);
void nyx_fdl_user_enable(nyx_fdl_user_t* self);
void nyx_fdl_user_set(nyx_fdl_user_t* self, shadow_memory_t* shadow_memory_state, nyx_fdl_t* nyx_fdl_state, uint64_t addr, uint64_t length);

uint32_t nyx_snapshot_user_fdl_restore(nyx_fdl_user_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);
void nyx_snapshot_nyx_fdl_user_save_root_pages(nyx_fdl_user_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);
