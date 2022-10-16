/*

Copyright (C) 2017 Sergej Schumilo

This file is part of QEMU-PT (HyperTrash / kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#pragma once
#include "qemu/osdep.h"
#include "migration/migration.h"
#include "monitor/monitor.h"
#include "nyx/khash.h"

#define IO_BUF_SIZE 32768

struct QEMUFile_tmp {
    void *ops;
    void *hooks;
    void *opaque;

    int64_t bytes_xfer;
    int64_t xfer_limit;

    int64_t      pos; // buffer start on write, end on read
    volatile int buf_index;
    int          buf_size; // 0 when writing
    uint8_t      buf[IO_BUF_SIZE];
};

struct fast_savevm_opaque_t {
    FILE     *f;
    uint8_t  *buf;
    size_t    buflen;
    uint64_t  pos;
    void     *output_buffer;
    uint32_t *output_buffer_size;
};

#define REALLOC_SIZE 0x8000

#define PRE_ALLOC_BLOCK_SIZE 0x8000000 /* 128 MB */

typedef struct state_reallocation_tmp_s {
    void   **copy;
    uint32_t fast_state_size;
    bool     enabled;
} state_reallocation_tmp_t;

typedef struct state_reallocation_s {
    void  **ptr;
    void  **copy;
    size_t *size;

    uint32_t fast_state_size;
    uint32_t fast_state_pos;


    void    **fptr;
    void    **opaque;
    uint32_t *version;

    uint32_t fast_state_fptr_size;
    uint32_t fast_state_fptr_pos;


    void  **get_fptr;
    void  **get_opaque;
    size_t *get_size;
    void  **get_data;

    uint32_t fast_state_get_fptr_size;
    uint32_t fast_state_get_fptr_pos;

    /* prevents heap fragmentation and additional 2GB mem usage */
    void    *pre_alloc_block;
    uint32_t pre_alloc_block_offset;

    state_reallocation_tmp_t tmp_snapshot;

} state_reallocation_t;

state_reallocation_t *state_reallocation_new(QEMUFile *f);

void fdl_fast_reload(state_reallocation_t *self);

void fdl_fast_create_tmp(state_reallocation_t *self);
void fdl_fast_enable_tmp(state_reallocation_t *self);
void fdl_fast_disable_tmp(state_reallocation_t *self);
