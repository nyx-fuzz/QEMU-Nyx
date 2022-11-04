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

#include "qemu/osdep.h"

#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <immintrin.h>

#include "block/qapi.h"
#include "exec/ram_addr.h"

#include "migration/global_state.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "migration/register.h"
#include "migration/savevm.h"
#include "migration/vmstate.h"

#include "qemu/main-loop.h"
#include "qemu/rcu_queue.h"

#include "sysemu/block-backend.h"
#include "sysemu/cpus.h"
#include "sysemu/kvm_int.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"

#include "nyx/debug.h"
#include "nyx/fast_vm_reload.h"
#include "nyx/state/snapshot_state.h"
#include "nyx/state/state.h"

#include "nyx/helpers.h"
#include "nyx/memory_access.h"

#include "nyx/snapshot/block/nyx_block_snapshot.h"
#include "nyx/snapshot/devices/nyx_device_state.h"
#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/backend/nyx_debug.h"
#include "nyx/snapshot/memory/block_list.h"
#include "nyx/snapshot/memory/shadow_memory.h"

FastReloadMemoryMode mode = RELOAD_MEMORY_MODE_DEBUG;

/* basic operations */

static void fast_snapshot_init_operation(fast_reload_t *self,
                                         const char    *snapshot_folder,
                                         bool           pre_snapshot)
{
    assert((snapshot_folder == NULL && pre_snapshot == false) || snapshot_folder);

    if (snapshot_folder) {
        self->device_state =
            nyx_device_state_init_from_snapshot(snapshot_folder, pre_snapshot);
        self->shadow_memory_state =
            shadow_memory_init_from_snapshot(snapshot_folder, pre_snapshot);
    } else {
        self->device_state        = nyx_device_state_init();
        self->shadow_memory_state = shadow_memory_init();
    }

    if (!pre_snapshot) {
        switch (mode) {
        case RELOAD_MEMORY_MODE_DEBUG:
            break;
        case RELOAD_MEMORY_MODE_DEBUG_QUIET:
            break;
        case RELOAD_MEMORY_MODE_FDL:
            self->fdl_state = nyx_fdl_init(self->shadow_memory_state);
            break;
        case RELOAD_MEMORY_MODE_FDL_DEBUG:
            self->fdl_state = nyx_fdl_init(self->shadow_memory_state);
            break;
        case RELOAD_MEMORY_MODE_DIRTY_RING:
            self->dirty_ring_state = nyx_dirty_ring_init(self->shadow_memory_state);
            break;
        case RELOAD_MEMORY_MODE_DIRTY_RING_DEBUG:
            self->dirty_ring_state = nyx_dirty_ring_init(self->shadow_memory_state);
            break;
        }

        self->fdl_user_state = nyx_fdl_user_init(self->shadow_memory_state);
        nyx_fdl_user_enable(self->fdl_user_state);
    }

    if (snapshot_folder) {
        self->block_state =
            nyx_block_snapshot_init_from_file(snapshot_folder, pre_snapshot);
    } else {
        self->block_state = nyx_block_snapshot_init();
    }

    memory_global_dirty_log_start();
    if (!pre_snapshot) {
        self->root_snapshot_created = true;
    }
}

static void fast_snapshot_restore_operation(fast_reload_t *self)
{
    uint32_t num_dirty_pages = 0;

    switch (mode) {
    case RELOAD_MEMORY_MODE_DEBUG:
        num_dirty_pages += nyx_snapshot_debug_restore(self->shadow_memory_state,
                                                      self->blocklist, true);
        break;
    case RELOAD_MEMORY_MODE_DEBUG_QUIET:
        num_dirty_pages += nyx_snapshot_debug_restore(self->shadow_memory_state,
                                                      self->blocklist, false);
        break;
    case RELOAD_MEMORY_MODE_FDL:
        num_dirty_pages += nyx_snapshot_nyx_fdl_restore(self->fdl_state,
                                                        self->shadow_memory_state,
                                                        self->blocklist);
        break;
    case RELOAD_MEMORY_MODE_FDL_DEBUG:
        num_dirty_pages += nyx_snapshot_nyx_fdl_restore(self->fdl_state,
                                                        self->shadow_memory_state,
                                                        self->blocklist);
        num_dirty_pages += nyx_snapshot_debug_restore(self->shadow_memory_state,
                                                      self->blocklist, true);
        break;
    case RELOAD_MEMORY_MODE_DIRTY_RING:
        num_dirty_pages +=
            nyx_snapshot_nyx_dirty_ring_restore(self->dirty_ring_state,
                                                self->shadow_memory_state,
                                                self->blocklist);
        break;
    case RELOAD_MEMORY_MODE_DIRTY_RING_DEBUG:
        num_dirty_pages +=
            nyx_snapshot_nyx_dirty_ring_restore(self->dirty_ring_state,
                                                self->shadow_memory_state,
                                                self->blocklist);
        num_dirty_pages += nyx_snapshot_debug_restore(self->shadow_memory_state,
                                                      self->blocklist, true);
        break;
    }

    num_dirty_pages += nyx_snapshot_user_fdl_restore(self->fdl_user_state,
                                                     self->shadow_memory_state,
                                                     self->blocklist);
    GET_GLOBAL_STATE()->num_dirty_pages = num_dirty_pages;
}

static inline void fast_snapshot_pre_create_incremental_operation(fast_reload_t *self)
{
    /* flush all pending block writes */
    bdrv_drain_all();
    memory_global_dirty_log_sync();

    nyx_device_state_switch_incremental(self->device_state);
    nyx_block_snapshot_switch_incremental(self->block_state);
}

static inline void fast_snapshot_create_incremental_operation(fast_reload_t *self)
{
    shadow_memory_prepare_incremental(self->shadow_memory_state);
    nyx_device_state_save_tsc_incremental(self->device_state);

    switch (mode) {
    case RELOAD_MEMORY_MODE_DEBUG:
        nyx_snapshot_debug_save_root_pages(self->shadow_memory_state,
                                           self->blocklist, true);
        break;
    case RELOAD_MEMORY_MODE_DEBUG_QUIET:
        nyx_snapshot_debug_save_root_pages(self->shadow_memory_state,
                                           self->blocklist, false);
        break;
    case RELOAD_MEMORY_MODE_FDL:
        nyx_snapshot_nyx_fdl_save_root_pages(self->fdl_state,
                                             self->shadow_memory_state,
                                             self->blocklist);
        break;
    case RELOAD_MEMORY_MODE_FDL_DEBUG:
        nyx_snapshot_nyx_fdl_save_root_pages(self->fdl_state,
                                             self->shadow_memory_state,
                                             self->blocklist);
        nyx_snapshot_debug_save_root_pages(self->shadow_memory_state,
                                           self->blocklist, true);
        break;
    case RELOAD_MEMORY_MODE_DIRTY_RING:
        nyx_snapshot_nyx_dirty_ring_save_root_pages(self->dirty_ring_state,
                                                    self->shadow_memory_state,
                                                    self->blocklist);
        break;
    case RELOAD_MEMORY_MODE_DIRTY_RING_DEBUG:
        nyx_snapshot_nyx_dirty_ring_save_root_pages(self->dirty_ring_state,
                                                    self->shadow_memory_state,
                                                    self->blocklist);
        nyx_snapshot_debug_save_root_pages(self->shadow_memory_state,
                                           self->blocklist, true);
        break;
    }

    nyx_snapshot_nyx_fdl_user_save_root_pages(self->fdl_user_state,
                                              self->shadow_memory_state,
                                              self->blocklist);
    shadow_memory_switch_snapshot(self->shadow_memory_state, true);

    kvm_arch_put_registers(qemu_get_cpu(0), KVM_PUT_FULL_STATE_FAST);
    qemu_get_cpu(0)->vcpu_dirty = false;
}


fast_reload_t *fast_reload_new(void)
{
    fast_reload_t *self = malloc(sizeof(fast_reload_t));
    memset(self, 0x0, sizeof(fast_reload_t));

    self->root_snapshot_created        = false;
    self->incremental_snapshot_enabled = false;

    self->bitmap_copy = NULL;

    return self;
}

void fast_reload_set_mode(fast_reload_t *self, FastReloadMemoryMode m)
{
    assert(!self->root_snapshot_created);
    mode = m;
}

FastReloadMemoryMode fast_reload_get_mode(fast_reload_t *self)
{
    return mode;
}

void fast_reload_init(fast_reload_t *self)
{
    self->blocklist = snapshot_page_blocklist_init();
}

/* fix this */
void fast_reload_destroy(fast_reload_t *self)
{
    /* TODO: complete me */

    // close(self->vmx_fdl_fd);
    // munmap(self->fdl_data, (self->guest_ram_size/0x1000)*8);

    /*
        munmap(self->ptr, self->guest_ram_size);

        free(self->black_list_pages);

        free(self);
    */
}

inline static void unlock_snapshot(const char *folder)
{
    char *info_file;
    char *lock_file;

    /* info file */
    assert(asprintf(&info_file, "%s/INFO.txt", folder) != -1);
    FILE *f_info = fopen(info_file, "w+b");
    if (GET_GLOBAL_STATE()->fast_reload_pre_image) {
        const char *msg = "THIS IS A NYX PRE IMAGE SNAPSHOT FOLDER!\n";
        fwrite(msg, strlen(msg), 1, f_info);
    } else {
        const char *msg = "THIS IS A NYX SNAPSHOT FOLDER!\n";
        fwrite(msg, strlen(msg), 1, f_info);
    }
    fclose(f_info);

    assert(asprintf(&lock_file, "%s/ready.lock", folder) != -1);
    int fd = open(lock_file, O_WRONLY | O_CREAT, S_IRWXU);
    close(fd);

    free(lock_file);
}

inline static void wait_for_snapshot(const char *folder)
{
    char *lock_file;

    assert(asprintf(&lock_file, "%s/ready.lock", folder) != -1);
    while (access(lock_file, F_OK) == -1) {
        sleep(1);
    }
    free(lock_file);
}

void fast_reload_serialize_to_file(fast_reload_t *self,
                                   const char    *folder,
                                   bool           is_pre_snapshot)
{
    nyx_trace();

    /* sanity check */
    if (!folder_exits(folder)) {
        nyx_error("Folder %s does not exist. Abort.\n", folder);
        assert(0);
    }

    /* shadow memory state */
    shadow_memory_serialize(self->shadow_memory_state, folder);

    /* device state */
    nyx_device_state_serialize(self->device_state, folder);

    /* block device state */
    nyx_block_snapshot_serialize(self->block_state, folder);

    /* NYX's state */
    serialize_state(folder, is_pre_snapshot);

    /* finalize snapshot */
    unlock_snapshot(folder);
}


static void fast_reload_create_from_snapshot(fast_reload_t *self,
                                             const char    *folder,
                                             bool           lock_iothread,
                                             bool           pre_snapshot)
{
    nyx_trace();

    assert(self != NULL);
    wait_for_snapshot(folder);

    nyx_debug_p(RELOAD_PREFIX,
                "=> CREATING FAST RELOAD SNAPSHOT FROM DUMP (location: %s)\n", folder);

    rcu_read_lock();

    bdrv_drain_all();
    bdrv_flush_all();

    cpu_synchronize_all_pre_loadvm();

    if (!pre_snapshot) {
        memory_global_dirty_log_stop();
        memory_global_dirty_log_sync();
    }

    fast_snapshot_init_operation(self, folder, pre_snapshot);

    rcu_read_unlock();

    if (!pre_snapshot) {
        deserialize_state(folder);
    }

    cpu_synchronize_all_post_init();
    qemu_get_cpu(0)->vcpu_dirty = true;
    kvm_arch_put_registers(qemu_get_cpu(0), KVM_PUT_FULL_STATE);
    if (!pre_snapshot) {
        nyx_device_state_save_tsc(self->device_state);
    }
}

void fast_reload_create_from_file(fast_reload_t *self,
                                  const char    *folder,
                                  bool           lock_iothread)
{
    nyx_trace();
    fast_reload_create_from_snapshot(self, folder, lock_iothread, false);
}

void fast_reload_create_from_file_pre_image(fast_reload_t *self,
                                            const char    *folder,
                                            bool           lock_iothread)
{
    nyx_trace();
    fast_reload_create_from_snapshot(self, folder, lock_iothread, true);
}

void fast_reload_create_in_memory(fast_reload_t *self)
{
    nyx_trace();
    assert(self != NULL);

    rcu_read_lock();

    bdrv_drain_all();
    bdrv_flush_all();

    cpu_synchronize_all_pre_loadvm();

    memory_global_dirty_log_stop();
    memory_global_dirty_log_sync();

    fast_snapshot_init_operation(self, NULL, false);

    rcu_read_unlock();
    cpu_synchronize_all_post_init();
}

void fast_reload_restore(fast_reload_t *self)
{
    assert(self != NULL);
    self->dirty_pages = 0;

    /* flush all pending block writes */
    bdrv_drain_all();
    memory_global_dirty_log_sync();

    nyx_block_snapshot_reset(self->block_state);

    nyx_device_state_restore(self->device_state);

    nyx_block_snapshot_flush(self->block_state);

    fast_snapshot_restore_operation(self);

    nyx_device_state_post_restore(self->device_state);
    kvm_arch_put_registers(qemu_get_cpu(0), KVM_PUT_FULL_STATE_FAST);
    qemu_get_cpu(0)->vcpu_dirty = false;

    return;
}


bool read_snapshot_memory(fast_reload_t *self, uint64_t address, void *ptr, size_t size)
{
    return shadow_memory_read_physical_memory(self->shadow_memory_state, address,
                                              ptr, size);
}

/* fix this */
void *fast_reload_get_physmem_shadow_ptr(fast_reload_t *self, uint64_t physaddr)
{
    abort(); /* TODO: fix this function first -> pc_piix memory split issue */

    /*
        assert(self != NULL);
    assert(!(physaddr&0xFFF));  // physaddr must be 4kb align !
    if (self->shadow_memory_regions){
        for(uint64_t j = 0; j < self->shadow_memory_regions; j++){
            if(physaddr >= self->ram_block_array[j]->offset && physaddr <
    (self->ram_block_array[j]->offset+self->ram_block_array[j]->used_length)){ return
    self->shadow_memory[j]+(physaddr-self->ram_block_array[j]->offset);
            }
        }
    }
    */
    return NULL; // not found ... sorry :(
}

void fast_reload_blacklist_page(fast_reload_t *self, uint64_t physaddr)
{
    assert(self->blocklist);
    snapshot_page_blocklist_add(self->blocklist, physaddr);
}

bool fast_reload_snapshot_exists(fast_reload_t *self)
{
    if (!self) {
        return false;
    }
    return true;
}

void fast_reload_create_tmp_snapshot(fast_reload_t *self)
{
    assert(self);

    self->dirty_pages = 0;
    fast_snapshot_pre_create_incremental_operation(self);

    if (!self->bitmap_copy) {
        self->bitmap_copy = new_coverage_bitmaps();
    }
    coverage_bitmap_copy_to_buffer(self->bitmap_copy);

    fast_snapshot_create_incremental_operation(self);
    self->incremental_snapshot_enabled = true;
}

void fast_reload_discard_tmp_snapshot(fast_reload_t *self)
{
    assert(self && self->incremental_snapshot_enabled);

    self->dirty_pages = 0;

    /* flush all pending block writes */
    bdrv_drain_all();
    memory_global_dirty_log_sync();

    fast_snapshot_restore_operation(self);

    shadow_memory_restore_memory(self->shadow_memory_state);
    shadow_memory_switch_snapshot(self->shadow_memory_state, false);

    nyx_device_state_disable_incremental(self->device_state);

    nyx_block_snapshot_disable_incremental(self->block_state);

    self->incremental_snapshot_enabled = false;
}

bool fast_reload_root_created(fast_reload_t *self)
{
    return self->root_snapshot_created;
}

bool fast_reload_tmp_created(fast_reload_t *self)
{
    return self->incremental_snapshot_enabled;
}

uint32_t get_dirty_page_num(fast_reload_t *self)
{
    if (self) {
        return self->dirty_pages;
    } else {
        return 0;
    }
}

bool fast_reload_set_bitmap(fast_reload_t *self)
{
    if (self->incremental_snapshot_enabled) {
        coverage_bitmap_copy_from_buffer(self->bitmap_copy);
        return true;
    }
    return false;
}

void fast_reload_qemu_user_fdl_set_dirty(fast_reload_t *self,
                                         MemoryRegion  *mr,
                                         uint64_t       addr,
                                         uint64_t       length)
{
    /* works only with PC.RAM's memory region */
    assert(mr->alias_offset == 0);

    nyx_fdl_user_set(self->fdl_user_state, self->shadow_memory_state,
                     self->fdl_state, addr, length);
}

void fast_reload_handle_dirty_ring_full(fast_reload_t *self)
{
    if (self->dirty_ring_state) {
        nyx_snapshot_nyx_dirty_ring_flush_and_collect(self->dirty_ring_state,
                                                      self->shadow_memory_state,
                                                      self->blocklist);
    } else {
        nyx_snapshot_nyx_dirty_ring_flush();
    }
}
