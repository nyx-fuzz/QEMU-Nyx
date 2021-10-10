#pragma once
#include <stdio.h>
#include "khash.h"
#include <stdint.h>


typedef struct sharedir_file_s{
  char* file;
  char* path;
  size_t size;
  uint64_t bytes_left; 
  time_t mod_time;
} sharedir_file_t;

KHASH_MAP_INIT_STR(SHAREDIR_LOOKUP, sharedir_file_t*)

typedef struct sharedir_s{
  char* dir;
	khash_t(SHAREDIR_LOOKUP) *lookup;
  FILE* last_file_f;
  sharedir_file_t* last_file_obj_ptr;
} sharedir_t;

sharedir_t* sharedir_new(void);
void sharedir_set_dir(sharedir_t* self, const char* dir);
uint64_t sharedir_request_file(sharedir_t* self, const char* file, uint8_t* page_buffer);
