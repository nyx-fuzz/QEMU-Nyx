#pragma once 

#include "nyx/snapshot/memory/block_list.h"
#include "nyx/snapshot/memory/shadow_memory.h"

#define STATE_BUFFER    0x8000000  /* up to 128MB */

#define USER_FDL_SLOTS 0x400000 /* fix this later */

#define KVM_VMX_FDL_SETUP_FD                _IO(KVMIO,  0xe5)
#define KVM_VMX_FDL_SET                     _IOW(KVMIO, 0xe6, __u64)
#define KVM_VMX_FDL_FLUSH                   _IO(KVMIO,  0xe7)
#define KVM_VMX_FDL_GET_INDEX               _IOR(KVMIO, 0xe8, __u64)


#define FAST_IN_RANGE(address, start, end) (address < end && address >= start)

#define FDL_MAX_AREAS 8

struct fdl_area{
	uint64_t base_address;
	uint64_t size;
	uint64_t mmap_bitmap_offset;
	uint64_t mmap_stack_offset;
    uint64_t mmap_bitmap_size;
	uint64_t mmap_stack_size;
};

struct fdl_conf{
	uint8_t num;
	uint64_t mmap_size;
	struct fdl_area areas[FDL_MAX_AREAS];
};

struct fdl_result{
	uint8_t num;
	uint64_t values[FDL_MAX_AREAS];
};

typedef struct nyx_fdl_s{
    /* vmx_fdl file descriptor */
    int vmx_fdl_fd;

    /* mmap mapping of fdl data -> might be useful for destructor */
    void* vmx_fdl_mmap;

    struct {
        uint64_t* stack;
        uint8_t* bitmap;
    }entry[FDL_MAX_AREAS];

    uint8_t num;
    
}nyx_fdl_t;

nyx_fdl_t* nyx_fdl_init(shadow_memory_t* self);
uint32_t nyx_snapshot_nyx_fdl_restore(nyx_fdl_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);

void nyx_snapshot_nyx_fdl_save_root_pages(nyx_fdl_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist);
