#pragma once 

#include <stdint.h>
#include <stdbool.h>
#include "nyx/snapshot/memory/shadow_memory.h"

typedef struct snapshot_page_blocklist_s{

  /* total number of blocklisted page frames */ 
	uint64_t pages_num;

  /* lookup array */
	uint64_t* pages;

  /* current size of our array */
	uint64_t pages_size;

  /* lookup bitmap of guest's physical memory layout (PCI-area between 3GB-4GB is set by default) */
  uint8_t* phys_bitmap;

  /* area of guest's physical memory (including RAM + PCI-hole) */
  uint64_t phys_area_size;
}snapshot_page_blocklist_t;


//snapshot_page_blocklist_t* snapshot_page_blocklist_init(shadow_memory_t* snapshot);

void snapshot_page_blocklist_add(snapshot_page_blocklist_t* self, uint64_t phys_addr);

/* returns true if phys_addr is on the blocklis */
static inline bool snapshot_page_blocklist_check_phys_addr(snapshot_page_blocklist_t* self, uint64_t phys_addr){
  return phys_addr < self->phys_area_size && test_bit(phys_addr>>12, (const unsigned long *)self->phys_bitmap) != 0;
}

snapshot_page_blocklist_t* snapshot_page_blocklist_init(void);
