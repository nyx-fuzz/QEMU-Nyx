#pragma once

#include "nyx/types.h"
#include "stdlib.h"
#include "stdint.h"

typedef enum MemSplitType {
    MEM_SPLIT_TYPE_INVALID,
    PC_PIIX_MEM_TYPE,
    Q35_MEM_MEM_TYPE,
} MemSplitType;


bool is_mem_mapping_supported(MemSplitType type);
uint64_t get_mem_split_start(void);
uint64_t get_mem_split_end(void);

uint64_t address_to_ram_offset(uint64_t offset);
uint64_t ram_offset_to_address(uint64_t offset);
