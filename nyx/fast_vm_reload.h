/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (HyperTrash / kAFL).

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

#pragma once

#include "qemu/osdep.h"
#include "monitor/monitor.h"
#include "qemu-common.h"
#include "sysemu/runstate.h"

#include "nyx/snapshot/memory/block_list.h"
#include "nyx/snapshot/memory/shadow_memory.h"
#include "nyx/snapshot/memory/backend/nyx_fdl.h"
#include "nyx/snapshot/memory/nyx_fdl_user.h"
#include "nyx/snapshot/devices/nyx_device_state.h"

#include "nyx/snapshot/block/nyx_block_snapshot.h"

#include "nyx/snapshot/memory/backend/nyx_dirty_ring.h"
#include "nyx/helpers.h"


typedef enum FastReloadMemoryMode {
  RELOAD_MEMORY_MODE_DEBUG, 						/* memcmp-based dirty tracing - it's super slow - only for debug purposes */
	RELOAD_MEMORY_MODE_DEBUG_QUIET,				/* debug mode in non-verbose mode */
  RELOAD_MEMORY_MODE_FDL, 							/* super fast page tracker build around KVM-PT's dirty tracker (FDL = fast dirty log) */
  RELOAD_MEMORY_MODE_FDL_DEBUG, 				/* FDL + debug mode */
  RELOAD_MEMORY_MODE_DIRTY_RING, 				/* fast page tracker build around KVM's dirty ring API */
  RELOAD_MEMORY_MODE_DIRTY_RING_DEBUG, 	/* dirty ring + debug mode */
} FastReloadMemoryMode;



typedef struct fast_reload_dump_head_s{
    uint32_t shadow_memory_regions; 
	uint32_t ram_region_index;
} fast_reload_dump_head_t; 


typedef struct fast_reload_s{

	FastReloadMemoryMode mode;

	/* memory snapshot */
	shadow_memory_t* shadow_memory_state;

	/* state of page frame blocklist */
	snapshot_page_blocklist_t* blocklist;

	/* state of FDL */
	nyx_fdl_t* fdl_state;

	/* dirty ring state */
	nyx_dirty_ring_t* dirty_ring_state;

	/* state of user-level FDL */
	nyx_fdl_user_t* fdl_user_state;

	/* nyx's serialized device state */
	nyx_device_state_t* device_state;

	nyx_block_t* block_state;

	bool root_snapshot_created;
	bool incremental_snapshot_enabled; 

	/* copy of the fuzzing bitmap & ijon state buffer */
	nyx_coverage_bitmap_copy_t* bitmap_copy;



	uint32_t dirty_pages;

} fast_reload_t;


fast_reload_t* fast_reload_new(void);


/* get rid of this */
void fast_reload_create_to_file(fast_reload_t* self, const char* folder, bool lock_iothread);
void fast_reload_create_from_file(fast_reload_t* self, const char* folder, bool lock_iothread);
void fast_reload_create_from_file_pre_image(fast_reload_t* self, const char* folder, bool lock_iothread);


/* keep this */
void fast_reload_create_in_memory(fast_reload_t* self);


void fast_reload_serialize_to_file(fast_reload_t* self, const char* folder, bool is_pre_snapshot);


void fast_reload_restore(fast_reload_t* self);
void fast_reload_blacklist_page(fast_reload_t* self, uint64_t physaddr);
void* fast_reload_get_physmem_shadow_ptr(fast_reload_t* self, uint64_t physaddr);
bool fast_reload_snapshot_exists(fast_reload_t* self);

bool read_snapshot_memory(fast_reload_t* self, uint64_t address, void* ptr, size_t size);

void fast_reload_destroy(fast_reload_t* self);

void fast_reload_qemu_user_fdl_set_dirty(fast_reload_t* self, MemoryRegion *mr, uint64_t addr, uint64_t length);

void fast_reload_create_tmp_snapshot(fast_reload_t* self);
void fast_reload_discard_tmp_snapshot(fast_reload_t* self);

bool fast_reload_root_created(fast_reload_t* self);
bool fast_reload_tmp_created(fast_reload_t* self);

bool fast_reload_set_bitmap(fast_reload_t* self);

uint32_t get_dirty_page_num(fast_reload_t* self);

void fast_reload_init(fast_reload_t* self);

void fast_reload_set_mode(fast_reload_t* self, FastReloadMemoryMode m);

void fast_reload_handle_dirty_ring_full(fast_reload_t* self);
FastReloadMemoryMode fast_reload_get_mode(fast_reload_t* self);
