#pragma once 

#include "qemu/osdep.h"

uint64_t get_rip(CPUState *cpu);

typedef struct nyx_coverage_bitmap_copy_s{
    void* coverage_bitmap;
    void* ijon_bitmap_buffer;
}nyx_coverage_bitmap_copy_t;

void nyx_abort(char* msg);
bool is_called_in_fuzzing_mode(const char* hypercall);

nyx_coverage_bitmap_copy_t* new_coverage_bitmaps(void);
void coverage_bitmap_reset(void);
void coverage_bitmap_copy_to_buffer(nyx_coverage_bitmap_copy_t* buffer);
void coverage_bitmap_copy_from_buffer(nyx_coverage_bitmap_copy_t* buffer);

int get_capstone_mode(int word_width_in_bits);

bool apply_capabilities(CPUState *cpu);

bool folder_exits(const char* path);
bool file_exits(const char* path);
