#include "qemu/osdep.h"
#include "sysemu/sysemu.h"
#include "cpu.h"
#include "qemu/main-loop.h"

#include "exec/ram_addr.h"
#include "qemu/rcu_queue.h"
#include "migration/migration.h"

#include "nyx/memory_access.h"

#include "nyx/snapshot/memory/backend/nyx_debug.h"
#include "nyx/fast_vm_reload.h"


/* init operation */
void nyx_snapshot_debug_pre_init(void){
  /* TODO */
}

/* init operation */
void nyx_snapshot_debug_init(fast_reload_t* self){
  /* TODO */
}

/* enable operation */
void nyx_snapshot_debug_enable(fast_reload_t* self){
  /* TODO */
}

/* restore operation */
uint32_t nyx_snapshot_debug_restore(shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist, bool verbose){
  uint32_t num_dirty_pages = 0;

  void* current_region = NULL;
  int counter = 0;
  for(uint8_t i = 0; i < shadow_memory_state->ram_regions_num; i++){

    if(shadow_memory_state->incremental_enabled){
      current_region = shadow_memory_state->ram_regions[i].incremental_region_ptr;
    }
    else{
      current_region = shadow_memory_state->ram_regions[i].snapshot_region_ptr;
    }

    for(uint64_t addr = 0; addr < shadow_memory_state->ram_regions[i].size; addr+=0x1000){

      void* host_addr = shadow_memory_state->ram_regions[i].host_region_ptr + addr;
      void* snapshot_addr = current_region + addr;
      uint64_t physical_addr = addr + shadow_memory_state->ram_regions[i].base;

      /* check first if the page is dirty (this is super slow, but quite useful for debugging) */
      if(memcmp(host_addr, snapshot_addr, TARGET_PAGE_SIZE)){
        /* check if page is not on the block list */ 
        if(snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) == false){
          //fprintf(stderr, "(2) DIRTY: 0x%lx (NUM: %d - OFFSET: 0x%lx)\n", physical_addr, i, addr);
          
          if(verbose){
            printf("%s -> (phys: 0x%lx) %p <-- %p [%d]\n", __func__, physical_addr, host_addr, snapshot_addr, shadow_memory_state->incremental_enabled);
            counter++;
          }
  
          memcpy(host_addr, snapshot_addr, TARGET_PAGE_SIZE);
          num_dirty_pages++;
        }
      }
    }
  }
          
  if(verbose){
    printf("TOTAL: %d\n", counter);
  }
  return num_dirty_pages;
}

void nyx_snapshot_debug_save_root_pages(shadow_memory_t* shadow_memory_state, snapshot_page_blocklist_t* blocklist, bool verbose){
  void* current_region = NULL;

  for(uint8_t i = 0; i < shadow_memory_state->ram_regions_num; i++){

    if(shadow_memory_state->incremental_enabled){
      current_region = shadow_memory_state->ram_regions[i].incremental_region_ptr;
    }
    else{
      current_region = shadow_memory_state->ram_regions[i].snapshot_region_ptr;
    }

    for(uint64_t addr = 0; addr < shadow_memory_state->ram_regions[i].size; addr+=0x1000){

      void* host_addr = shadow_memory_state->ram_regions[i].host_region_ptr + addr;
      void* snapshot_addr = current_region + addr;
      uint64_t physical_addr = addr + shadow_memory_state->ram_regions[i].base;
      void* incremental_addr = shadow_memory_state->ram_regions[i].incremental_region_ptr + addr;

      /* check first if the page is dirty (this is super slow, but quite useful for debugging) */
      if(memcmp(host_addr, snapshot_addr, TARGET_PAGE_SIZE)){
        /* check if page is not on the block list */ 
        if(snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) == false){
          //fprintf(stderr, "(2) DIRTY: 0x%lx (NUM: %d - OFFSET: 0x%lx)\n", physical_addr, i, addr);
          
          if(verbose && !shadow_memory_is_root_page_tracked(shadow_memory_state, addr, i)){
            printf("%s -> %p <-- %p [%d]\n", __func__, host_addr, snapshot_addr, shadow_memory_state->incremental_enabled);
          }

          shadow_memory_track_dirty_root_pages(shadow_memory_state, addr, i); 
          memcpy(incremental_addr, host_addr, TARGET_PAGE_SIZE);
        }
      }
    }
  }
}

/* set operation */
void nyx_snapshot_debug_set(fast_reload_t* self){
  /* TODO */
}