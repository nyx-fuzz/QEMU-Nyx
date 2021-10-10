#pragma once 

#include "qemu/osdep.h"

uint64_t get_rip(CPUState *cpu);
void fuzz_bitmap_reset(void);
void fuzz_bitmap_copy_to_buffer(void* buffer);
void fuzz_bitmap_copy_from_buffer(void* buffer);

int get_capstone_mode(int word_width_in_bits);

void apply_capabilities(CPUState *cpu);

bool folder_exits(const char* path);
bool file_exits(const char* path);
