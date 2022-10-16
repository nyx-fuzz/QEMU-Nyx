#pragma once

#include <stdint.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE qemu_real_host_page_size
#endif

#define BITMAP_SIZE(x)      ((x / PAGE_SIZE) / 8)
#define DIRTY_STACK_SIZE(x) ((x / PAGE_SIZE) * sizeof(uint64_t))


uint64_t get_ram_size(void);
