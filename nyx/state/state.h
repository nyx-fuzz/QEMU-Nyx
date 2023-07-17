/*

Copyright (C) 2019 Sergej Schumilo

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

#include "nyx/auxiliary_buffer.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/fast_vm_reload_sync.h"
#include "nyx/page_cache.h"
#include "nyx/redqueen.h"
#include "nyx/redqueen_patch.h"
#include "nyx/sharedir.h"
#include "nyx/synchronization.h"
#include "nyx/types.h"
#include "nyx/mem_split.h"

#include <libxdc.h>

#define INTEL_PT_MAX_RANGES 4

typedef struct qemu_nyx_state_s {
    /* set if PT mode is supported */
    bool nyx_pt;

    char    *workdir_path;
    uint32_t worker_id;

    /* FAST VM RELOAD */
    bool                   fast_reload_enabled;
    bool                   fast_reload_mode;
    char                  *fast_reload_path;
    char                  *fast_reload_pre_path;
    bool                   fast_reload_pre_image;
    fast_reload_t         *fast_reload_snapshot;
    fast_vm_reload_sync_t *reload_state;

    /* PAGE CACHE */
    page_cache_t *page_cache;

    /* Decoder */
    libxdc_t *decoder;

    /* REDQUEEN */
    bool        redqueen_enable_pending;
    bool        redqueen_disable_pending;
    int         redqueen_instrumentation_mode;
    bool        redqueen_update_blacklist;
    bool        patches_enable_pending;
    bool        patches_disable_pending;
    redqueen_t *redqueen_state;

    /* Intel PT Options (not migratable) */
    uint64_t      pt_c3_filter;
    volatile bool pt_ip_filter_enabled[4];
    bool pt_trace_mode; // enabled by default; disabled if compile-time tracing is implemented by agent

    /* disabled by default; enable to force usage of PT tracing
     * (useful for targets that use compile-time tracing and redqueen at the same
     * time (which obviously relies on PT traces)) This mode is usually enabled by
     * the fuzzing logic by enabling trace mode.
     * *** THIS FEATURES IS STILL EXPERIMENTAL ***
     * */
    bool pt_trace_mode_force;

    uint32_t pt_trace_size; // trace size counter
    uint32_t bb_coverage;   // trace size counter

    /* mmap Options (not migratable) */
    int      shared_bitmap_fd;
    uint32_t shared_bitmap_size;      /* size of the shared memory file */
    uint32_t shared_bitmap_real_size; /* actual size of the bitmap */
    void    *shared_bitmap_ptr;

    int      shared_payload_buffer_fd;
    uint32_t shared_payload_buffer_size;

    int      shared_ijon_bitmap_fd;
    uint32_t shared_ijon_bitmap_size;
    void    *shared_ijon_bitmap_ptr;

    /* Intel PT Options (migratable) */
    bool     pt_ip_filter_configured[4];
    uint64_t pt_ip_filter_a[4];
    uint64_t pt_ip_filter_b[4];

    /* OPTIONS (MIGRATABLE VIA FAST SNAPSHOTS) */
    uint64_t   parent_cr3;
    uint8_t    disassembler_word_width;
    bool       nested;
    uint64_t   payload_buffer;
    uint32_t   nested_payload_pages_num;
    uint64_t  *nested_payload_pages;
    bool       protect_payload_buffer;
    bool       discard_tmp_snapshot;
    mem_mode_t mem_mode;
    uint32_t   input_buffer_size;


    /* NON MIGRATABLE OPTION */
    timeout_detector_t timeout_detector;

    bool     decoder_page_fault;
    uint64_t decoder_page_fault_addr;

    bool     dump_page;
    uint64_t dump_page_addr;

    bool in_fuzzing_mode;
    bool in_reload_mode;
    bool starved;
    bool trace_mode;

    bool shutdown_requested;
    bool cow_cache_full;

    bool in_redqueen_reload_mode;

    uint32_t num_dirty_pages;

    bool get_host_config_done;
    bool set_agent_config_done;

    MemSplitType mem_mapping_type;
    uint64_t mem_mapping_low;
    uint64_t mem_mapping_high;

    uint32_t auxilary_buffer_size;
    char* hprintf_tmp_buffer;

    /* capabilites */
    uint8_t  cap_timeout_detection;
    uint8_t  cap_only_reload_mode;
    uint8_t  cap_compile_time_tracing;
    uint8_t  cap_ijon_tracing;
    uint64_t cap_cr3;
    uint64_t cap_compile_time_tracing_buffer_vaddr;
    uint64_t cap_ijon_tracing_buffer_vaddr;
    uint64_t cap_coverage_bitmap_size;

    auxilary_buffer_t       *auxilary_buffer;
    auxilary_buffer_config_t shadow_config;
    sharedir_t              *sharedir;

    QTAILQ_HEAD(, kvm_sw_breakpoint) redqueen_breakpoints;
} qemu_nyx_state_t;

extern qemu_nyx_state_t global_state;

#define GET_GLOBAL_STATE() (&global_state)

void           state_init_global(void);
fast_reload_t *get_fast_reload_snapshot(void);
void           set_fast_reload_mode(bool mode);
void           set_fast_reload_path(const char *path);
void           set_fast_reload_pre_image(void);


void enable_fast_reloads(void);

/* Page Cache */
void          init_page_cache(char *path);
page_cache_t *get_page_cache(void);

void init_redqueen_state(void);

redqueen_t *get_redqueen_state(void);

void init_aux_buffer(const char *filename);
void set_fast_reload_pre_path(const char *path);

void set_payload_buffer(uint64_t payload_buffer);
void set_payload_pages(uint64_t *payload_pages, uint32_t pages);

void set_workdir_path(char *workdir);
void set_aux_buffer_size(uint32_t aux_buffer_size);
