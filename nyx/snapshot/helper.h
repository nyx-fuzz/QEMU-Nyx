#pragma once 

#include <stdint.h>

/* don't! */
#define MAX_REGIONS 8

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define BITMAP_SIZE(x) ((x/PAGE_SIZE)/8)
#define DIRTY_STACK_SIZE(x) ((x/PAGE_SIZE)*sizeof(uint64_t))


uint64_t get_ram_size(void);
