#pragma once 

#include "nyx/snapshot/memory/block_list.h"
#include "nyx/snapshot/memory/shadow_memory.h"

struct kvm_dirty_gfn {
	uint32_t flags;
	uint32_t slot;
	uint64_t offset;
};

typedef struct slot_s{
    bool enabled;               /* set if slot is not marked as read-only */

    uint8_t region_id;          /* shadow_memory region id */
    uint64_t region_offset;     /* shadow_memory region offset*/

    void* bitmap;

    uint64_t bitmap_size; // remove me later
    uint64_t* stack;
    uint64_t stack_ptr;
} slot_t;

typedef struct nyx_dirty_ring_s{
    slot_t* kvm_region_slots;
    uint8_t kvm_region_slots_num;

} nyx_dirty_ring_t;

/* must be called before KVM_SET_USER_MEMORY_REGION & KVM_CREATE_VCPU */
void nyx_dirty_ring_early_init(int kvm_fd, int vm_fd);

/* must be called right after KVM_CREATE_VCPU */
void nyx_dirty_ring_pre_init(int kvm_fd, int vm_fd);

nyx_dirty_ring_t* nyx_dirty_ring_init(shadow_memory_t* shadow_memory);

uint32_t nyx_snapshot_nyx_dirty_ring_restore(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);
void nyx_snapshot_nyx_dirty_ring_save_root_pages(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);

void nyx_snapshot_nyx_dirty_ring_flush(void);
void nyx_snapshot_nyx_dirty_ring_flush_and_collect(nyx_dirty_ring_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);
