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

#include "qemu/osdep.h"

#include <stdint.h>
#include <stdio.h>

#include "sysemu/kvm.h"
#include "nyx/auxiliary_buffer.h"
#include "nyx/debug.h"
#include "nyx/fast_vm_reload_sync.h"
#include "nyx/helpers.h"
#include "nyx/memory_access.h"
#include "nyx/sharedir.h"
#include "nyx/state/state.h"

/* global singleton */
qemu_nyx_state_t global_state;

#define LIBXDC_RELEASE_VERSION_REQUIRED 2

void state_init_global(void)
{
    nyx_trace();

    /* safety first */
    assert(libxdc_get_release_version() == LIBXDC_RELEASE_VERSION_REQUIRED);

    global_state.nyx_pt = false;

    global_state.workdir_path = NULL;
    global_state.worker_id    = 0xffff;

    global_state.fast_reload_enabled   = false;
    global_state.fast_reload_mode      = false;
    global_state.fast_reload_path      = NULL;
    global_state.fast_reload_pre_path  = NULL;
    global_state.fast_reload_pre_image = false;

    global_state.fast_reload_snapshot = fast_reload_new();
    global_state.reload_state         = init_fast_vm_reload_sync();

    global_state.decoder = NULL;

    global_state.page_cache = NULL;

    global_state.redqueen_enable_pending       = false;
    global_state.redqueen_disable_pending      = false;
    global_state.redqueen_instrumentation_mode = 0;
    global_state.redqueen_update_blacklist     = false;
    global_state.patches_enable_pending        = false;
    global_state.patches_disable_pending       = false;
    global_state.redqueen_state                = NULL;

    for (uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++) {
        global_state.pt_ip_filter_configured[i] = false;
        global_state.pt_ip_filter_enabled[i]    = false;
        global_state.pt_ip_filter_a[i]          = 0x0;
        global_state.pt_ip_filter_b[i]          = 0x0;
    }
    global_state.pt_c3_filter = 0;

    global_state.parent_cr3               = 0;
    global_state.disassembler_word_width  = 64;
    global_state.nested                   = false;
    global_state.payload_buffer           = 0;
    global_state.nested_payload_pages     = NULL;
    global_state.nested_payload_pages_num = 0;
    global_state.protect_payload_buffer   = 0;
    global_state.discard_tmp_snapshot     = 0;
    global_state.mem_mode                 = mm_unkown;

    init_timeout_detector(&(global_state.timeout_detector));

    global_state.in_fuzzing_mode    = false;
    global_state.in_reload_mode     = true;
    global_state.starved            = false;
    global_state.trace_mode         = false;
    global_state.shutdown_requested = false;
    global_state.cow_cache_full     = false;

    global_state.auxilary_buffer_size = DEFAULT_AUX_BUFFER_SIZE;
    global_state.auxilary_buffer = NULL;
    memset(&global_state.shadow_config, 0x0, sizeof(auxilary_buffer_config_t));

    global_state.decoder_page_fault      = false;
    global_state.decoder_page_fault_addr = 0x0;

    global_state.dump_page      = false;
    global_state.dump_page_addr = 0x0;

    global_state.in_redqueen_reload_mode = false;

    global_state.pt_trace_mode       = true;
    global_state.pt_trace_mode_force = false;

    global_state.num_dirty_pages = 0;

    global_state.get_host_config_done  = false;
    global_state.set_agent_config_done = false;

    global_state.mem_mapping_type = MEM_SPLIT_TYPE_INVALID;

    global_state.sharedir = sharedir_new();
    global_state.mem_mapping_low = 0;
    global_state.mem_mapping_high = 0;

    global_state.shared_bitmap_fd        = 0;
    global_state.shared_bitmap_size      = 0;
    global_state.shared_bitmap_real_size = 0;
    global_state.shared_bitmap_ptr       = NULL;

    global_state.shared_payload_buffer_fd   = 0;
    global_state.shared_payload_buffer_size = 0;

    global_state.shared_ijon_bitmap_fd   = 0;
    global_state.shared_ijon_bitmap_size = 0;
    global_state.shared_ijon_bitmap_ptr  = NULL;

    global_state.pt_trace_size = 0;
    global_state.bb_coverage   = 0;

    global_state.cap_timeout_detection                 = 0;
    global_state.cap_only_reload_mode                  = 0;
    global_state.cap_compile_time_tracing              = 0;
    global_state.cap_ijon_tracing                      = 0;
    global_state.cap_cr3                               = 0;
    global_state.cap_compile_time_tracing_buffer_vaddr = 0;
    global_state.cap_ijon_tracing_buffer_vaddr         = 0;

    QTAILQ_INIT(&global_state.redqueen_breakpoints);
}


fast_reload_t *get_fast_reload_snapshot(void)
{
    return global_state.fast_reload_snapshot;
}

void set_fast_reload_mode(bool mode)
{
    global_state.fast_reload_mode = mode;
}

void set_fast_reload_path(const char *path)
{
    assert(global_state.fast_reload_path == NULL);
    global_state.fast_reload_path = malloc(strlen(path) + 1);
    strcpy(global_state.fast_reload_path, path);
}

void set_fast_reload_pre_path(const char *path)
{
    assert(global_state.fast_reload_pre_path == NULL);
    global_state.fast_reload_pre_path = malloc(strlen(path) + 1);
    strcpy(global_state.fast_reload_pre_path, path);
}

void set_fast_reload_pre_image(void)
{
    assert(global_state.fast_reload_pre_path != NULL);
    global_state.fast_reload_pre_image = true;
}

void enable_fast_reloads(void)
{
    assert(global_state.fast_reload_path != NULL);
    global_state.fast_reload_enabled = true;
}

void init_page_cache(char *path)
{
    assert(global_state.page_cache == NULL);
    global_state.page_cache = page_cache_new((CPUState *)qemu_get_cpu(0), path);
}

page_cache_t *get_page_cache(void)
{
    assert(global_state.page_cache);
    return global_state.page_cache;
}

void init_redqueen_state(void)
{
    global_state.redqueen_state =
        new_rq_state((CPUState *)qemu_get_cpu(0), get_page_cache());
}


redqueen_t *get_redqueen_state(void)
{
    assert(global_state.redqueen_state != NULL);
    return global_state.redqueen_state;
}

static void *alloc_auxiliary_buffer(const char *file, uint32_t aux_buffer_size)
{
    void       *ptr;
    struct stat st;
    int         fd = open(file, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG | S_IRWXO);

    assert(ftruncate(fd, aux_buffer_size) == 0);
    stat(file, &st);

    nyx_debug_p(INTERFACE_PREFIX, "new aux buffer file: (max size: %x) %lx\n",
                aux_buffer_size, st.st_size);

    assert(aux_buffer_size == st.st_size);
    ptr = mmap(0, aux_buffer_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        nyx_error("aux buffer allocation failed!\n");
        return (void *)-1;
    }
    return ptr;
}

void init_aux_buffer(const char *filename)
{
    global_state.auxilary_buffer =
        (auxilary_buffer_t *)alloc_auxiliary_buffer(filename, global_state.auxilary_buffer_size);
    init_auxiliary_buffer(global_state.auxilary_buffer, global_state.auxilary_buffer_size);

    global_state.hprintf_tmp_buffer = (char *)malloc(misc_size());
    memset(global_state.hprintf_tmp_buffer, 0, misc_size());
}

void set_payload_buffer(uint64_t payload_buffer)
{
    assert(global_state.payload_buffer == 0 && global_state.nested == false);
    global_state.payload_buffer = payload_buffer;
    global_state.nested         = false;
}

void set_payload_pages(uint64_t *payload_pages, uint32_t pages)
{
    assert(global_state.nested_payload_pages == NULL &&
           global_state.nested_payload_pages_num == 0);
    global_state.nested_payload_pages = (uint64_t *)malloc(sizeof(uint64_t) * pages);
    global_state.nested_payload_pages_num = pages;
    memcpy(global_state.nested_payload_pages, payload_pages, sizeof(uint64_t) * pages);
    global_state.nested = true;
}

void set_workdir_path(char *workdir)
{
    assert(workdir && !global_state.workdir_path);
    assert(asprintf(&global_state.workdir_path, "%s", workdir) != -1);
}

void set_aux_buffer_size(uint32_t aux_buffer_size)
{
    assert(aux_buffer_size >= DEFAULT_AUX_BUFFER_SIZE && (aux_buffer_size & 0xfff) == 0 );
    assert(global_state.auxilary_buffer == NULL);

    global_state.auxilary_buffer_size = aux_buffer_size;
}