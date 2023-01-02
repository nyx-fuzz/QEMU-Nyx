#include "qemu/osdep.h"
#include "nyx/state/state.h"
#include "nyx/mem_split.h"

bool is_mem_mapping_supported(MemSplitType type){
    return GET_GLOBAL_STATE()->mem_mapping_type != MEM_SPLIT_TYPE_INVALID;
}

uint64_t get_mem_split_start(void){
    assert(is_mem_mapping_supported(GET_GLOBAL_STATE()->mem_mapping_type));
    return GET_GLOBAL_STATE()->mem_mapping_low;
}

uint64_t get_mem_split_end(void){
    assert(is_mem_mapping_supported(GET_GLOBAL_STATE()->mem_mapping_type));
    assert(GET_GLOBAL_STATE()->mem_mapping_high != 0);
    return GET_GLOBAL_STATE()->mem_mapping_high;
}

uint64_t address_to_ram_offset(uint64_t offset){
    assert(is_mem_mapping_supported(GET_GLOBAL_STATE()->mem_mapping_type));
    if(GET_GLOBAL_STATE()->mem_mapping_high == 0){
        assert(offset <= GET_GLOBAL_STATE()->mem_mapping_low);
        return offset;
    }
    else{
        return offset >= GET_GLOBAL_STATE()->mem_mapping_high ? (offset - GET_GLOBAL_STATE()->mem_mapping_high) + GET_GLOBAL_STATE()->mem_mapping_low : offset;
    }
}

uint64_t ram_offset_to_address(uint64_t offset){

    assert(is_mem_mapping_supported(GET_GLOBAL_STATE()->mem_mapping_type));
    if(GET_GLOBAL_STATE()->mem_mapping_high == 0){
        assert(offset <= GET_GLOBAL_STATE()->mem_mapping_low);
        return offset;
    }
    else{
        return offset >= GET_GLOBAL_STATE()->mem_mapping_low ? (offset - GET_GLOBAL_STATE()->mem_mapping_low) + GET_GLOBAL_STATE()->mem_mapping_high : offset;
    }
}
