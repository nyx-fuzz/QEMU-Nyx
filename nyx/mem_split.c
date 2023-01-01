#include "qemu/osdep.h"
#include "nyx/state/state.h"
#include "nyx/mem_split.h"

#define PC_PIIX_LOW_MEM_SPLIT_START 0xe0000000

#define PC_PIIX_MEM_SPLIT_START 0x0C0000000
#define PC_PIXX_MEM_SPLIT_END   0x100000000

#define Q35_MEM_SPLIT_START 0x080000000
#define Q35_MEM_SPLIT_END   0x100000000

#define Q35_LOW_MEM_SPLIT_START 0x0b0000000

bool is_mem_mapping_supported(MemSplitType type){
    return type == PC_PIIX_MEM_LOW_TYPE || type == PC_PIIX_MEM_TYPE || type == Q35_MEM_MEM_LOW_TYPE || type == Q35_MEM_MEM_TYPE;
}

uint64_t get_mem_split_start(void){
    switch(GET_GLOBAL_STATE()->mem_mapping_type){
        case PC_PIIX_MEM_LOW_TYPE: 
            return PC_PIIX_LOW_MEM_SPLIT_START;
        case PC_PIIX_MEM_TYPE: 
            return PC_PIIX_MEM_SPLIT_START;
        case Q35_MEM_MEM_LOW_TYPE:
            return Q35_LOW_MEM_SPLIT_START;
        case Q35_MEM_MEM_TYPE:
            return Q35_MEM_SPLIT_START;
        default:
            abort();
    }
}

uint64_t get_mem_split_end(void){
    switch(GET_GLOBAL_STATE()->mem_mapping_type){
        case PC_PIIX_MEM_TYPE: 
            return PC_PIXX_MEM_SPLIT_END;
        case Q35_MEM_MEM_TYPE:
            return Q35_MEM_SPLIT_END;
        default:
            abort();
    }
}

uint64_t address_to_ram_offset(uint64_t offset){
    switch(GET_GLOBAL_STATE()->mem_mapping_type){
        case PC_PIIX_MEM_LOW_TYPE:
            if(offset >= PC_PIIX_LOW_MEM_SPLIT_START){
                abort();
            }
            return offset;
        case PC_PIIX_MEM_TYPE: 
            return offset >= PC_PIXX_MEM_SPLIT_END ? (offset - PC_PIXX_MEM_SPLIT_END) + PC_PIIX_MEM_SPLIT_START : offset;
        case Q35_MEM_MEM_TYPE:
            return offset >= Q35_MEM_SPLIT_END ? (offset - Q35_MEM_SPLIT_END) + Q35_MEM_SPLIT_START : offset;
        case Q35_MEM_MEM_LOW_TYPE:
            if(offset >= Q35_LOW_MEM_SPLIT_START){
                abort();
            }
            return offset;
        default:
            abort();
    }
}

uint64_t ram_offset_to_address(uint64_t offset){
    switch(GET_GLOBAL_STATE()->mem_mapping_type){
        case PC_PIIX_MEM_LOW_TYPE:
            if(offset >= PC_PIIX_LOW_MEM_SPLIT_START){
                abort();
            }
            return offset;
        case PC_PIIX_MEM_TYPE: 
            return offset >= PC_PIIX_MEM_SPLIT_START ? (offset - PC_PIIX_MEM_SPLIT_START) + PC_PIXX_MEM_SPLIT_END : offset;;
        case Q35_MEM_MEM_TYPE:
            return offset >= Q35_MEM_SPLIT_START ? (offset - Q35_MEM_SPLIT_START) + Q35_MEM_SPLIT_END : offset;
        case Q35_MEM_MEM_LOW_TYPE:
            if(offset >= Q35_LOW_MEM_SPLIT_START){
                abort();
            }
            return offset;
        default:
            abort();
    }
}
