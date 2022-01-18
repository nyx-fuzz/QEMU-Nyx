#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "target/i386/cpu.h"
#include "qemu/main-loop.h"

#include "exec/ram_addr.h"
#include "qemu/rcu_queue.h"
#include "migration/migration.h"

#include "nyx/memory_access.h"

#include <linux/kvm.h>
#include <sys/ioctl.h>

#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/shadow_memory.h"
#include "nyx/snapshot/memory/nyx_fdl_user.h"

/* debug option */
//#define DEBUG_USER_FDL

/* init operation */
nyx_fdl_user_t* nyx_fdl_user_init(shadow_memory_t* shadow_memory_state){

    nyx_fdl_user_t* self = malloc(sizeof(nyx_fdl_user_t));
    memset(self, 0, sizeof(nyx_fdl_user_t));

    /* get rid of that? */
    self->num = shadow_memory_state->ram_regions_num;

    for(uint8_t i = 0; i < shadow_memory_state->ram_regions_num; i++){
        self->entry[i].stack = malloc(DIRTY_STACK_SIZE(shadow_memory_state->ram_regions[i].size));
        self->entry[i].bitmap = malloc(BITMAP_SIZE(shadow_memory_state->ram_regions[i].size));
    }
    //printf("%s -> %p\n", __func__, self);
    return self;
}

/* enable operation */
void nyx_fdl_user_enable(nyx_fdl_user_t* self){
    assert(self);
    self->enabled = true;
}

static void nyx_snapshot_user_fdl_reset(nyx_fdl_user_t* self){
    if(self){
        for(uint8_t i = 0; i < self->num; i++){
            self->entry[i].pos = 0;
        }
    }
}

/* reset operation */
uint32_t nyx_snapshot_user_fdl_restore(nyx_fdl_user_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){
    uint32_t num_dirty_pages = 0;
    if(self){

        void* current_region = NULL;


        for(uint8_t i = 0; i < self->num; i++){
#ifdef DEBUG_USER_FDL
            printf("User   -> [%d] %ld \t%ldKB\n", i, self->entry[i].pos, (0x1000*self->entry[i].pos)>>0x10);
#endif

            if(shadow_memory_state->incremental_enabled){
                current_region = shadow_memory_state->ram_regions[i].incremental_region_ptr;
            }
            else{
                current_region = shadow_memory_state->ram_regions[i].snapshot_region_ptr;
            }

            for(uint64_t j = 0; j < self->entry[i].pos; j++){
                uint64_t physical_addr = self->entry[i].stack[j];
                uint64_t entry_offset_addr = physical_addr - shadow_memory_state->ram_regions[i].base;

                void* host_addr = shadow_memory_state->ram_regions[i].host_region_ptr + entry_offset_addr;
                void* snapshot_addr = current_region + entry_offset_addr;

                if(snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) == true){
                    continue;
                }

#ifdef DEBUG_USER_FDL
                printf("%s -> %p <-- %p\n", __func__, host_addr, snapshot_addr);
#endif
                clear_bit(entry_offset_addr>>12, (void*)self->entry[i].bitmap);
                memcpy(host_addr, snapshot_addr, TARGET_PAGE_SIZE);
                num_dirty_pages++;
            }

        }

    }

    nyx_snapshot_user_fdl_reset(self);
    return num_dirty_pages;
}

/* set operation (mark pf as dirty) */ 
void nyx_fdl_user_set(nyx_fdl_user_t* self, shadow_memory_t* shadow_memory_state, nyx_fdl_t* nyx_fdl_state, uint64_t addr, uint64_t length){
    if(length < 0x1000){
        length = 0x1000;
    }

    if(self && self->enabled && length >= 0x1000){

		uint8_t ram_area = 0xff;

        /* optimize this? */
        addr = ram_offset_to_address(addr);


		switch(MAX_REGIONS-shadow_memory_state->ram_regions_num){
			case 0:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[7].base, shadow_memory_state->ram_regions[7].base+(shadow_memory_state->ram_regions[7].size-1)) ? 7 : ram_area;
			case 1:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[6].base, shadow_memory_state->ram_regions[6].base+(shadow_memory_state->ram_regions[6].size-1)) ? 6 : ram_area;
			case 2: 
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[5].base, shadow_memory_state->ram_regions[5].base+(shadow_memory_state->ram_regions[5].size-1)) ? 5 : ram_area;
			case 3:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[4].base, shadow_memory_state->ram_regions[4].base+(shadow_memory_state->ram_regions[4].size-1)) ? 4 : ram_area;
			case 4:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[3].base, shadow_memory_state->ram_regions[3].base+(shadow_memory_state->ram_regions[3].size-1)) ? 3 : ram_area;
			case 5:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[2].base, shadow_memory_state->ram_regions[2].base+(shadow_memory_state->ram_regions[2].size-1)) ? 2 : ram_area;
			case 6:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[1].base, shadow_memory_state->ram_regions[1].base+(shadow_memory_state->ram_regions[1].size-1)) ? 1 : ram_area;
			case 7:
				ram_area = FAST_IN_RANGE(addr, shadow_memory_state->ram_regions[0].base, shadow_memory_state->ram_regions[0].base+(shadow_memory_state->ram_regions[0].size-1)) ? 0 : ram_area;
			default:
				break;
		}

	    //ram_area = FAST_IN_RANGE(addr, fdl_data2.entry[0].base, fdl_data2.entry[0].base+(fdl_data2.entry[0].size-1)) ? 0 : ram_area;

		if(ram_area == 0xff){
			printf("ERROR: %s %lx [%d]\n", __func__, addr, ram_area);
            abort();
			return;
		}


        for(uint64_t offset = 0; offset < length; offset+=0x1000){

            uint64_t current_addr = (addr+offset) & 0xFFFFFFFFFFFFF000;

            long pfn = (long) ((current_addr-shadow_memory_state->ram_regions[ram_area].base)>>12);

            assert(self->entry[ram_area].bitmap);

            /* todo -> better handling of nyx_fdl_state */
            if(!test_bit(pfn, (const unsigned long*)self->entry[ram_area].bitmap)){
                set_bit(pfn, (unsigned long*)self->entry[ram_area].bitmap);

                self->entry[ram_area].stack[self->entry[ram_area].pos] =  current_addr & 0xFFFFFFFFFFFFF000;
                self->entry[ram_area].pos++;

#ifdef DEBUG_USER_FDL
                printf("USER DIRTY -> 0x%lx\n", current_addr & 0xFFFFFFFFFFFFF000);
#endif
            }
        }
    }
}

void nyx_snapshot_nyx_fdl_user_save_root_pages(nyx_fdl_user_t* self, shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist){

    for(uint8_t i = 0; i < self->num; i++){
#ifdef DEBUG_USER_FDL
        printf("User   -> [%d] %ld \t%ldKB\n", i, self->entry[i].pos, (0x1000*self->entry[i].pos)>>0x10);
#endif

        for(uint64_t j = 0; j < self->entry[i].pos; j++){
            uint64_t physical_addr = self->entry[i].stack[j];
            uint64_t entry_offset_addr = physical_addr - shadow_memory_state->ram_regions[i].base;

            void* host_addr = shadow_memory_state->ram_regions[i].host_region_ptr + entry_offset_addr;
            void* incremental_addr = shadow_memory_state->ram_regions[i].incremental_region_ptr + entry_offset_addr;
     
            if(snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) == true){
                printf("%s: 0x%lx is dirty\n", __func__, physical_addr);
                continue;
            }
#ifdef DEBUG_USER_FDL
            printf("%s -> %p <-- %p\n", __func__, incremental_addr, host_addr);
#endif
            //printf("%s -> %p <-- %p\n", __func__, incremental_addr, host_addr);

          	clear_bit(entry_offset_addr>>12, (void*)self->entry[i].bitmap);
            shadow_memory_track_dirty_root_pages(shadow_memory_state, entry_offset_addr, i);
            memcpy(incremental_addr, host_addr, TARGET_PAGE_SIZE);

        }
    }

    nyx_snapshot_user_fdl_reset(self);
}