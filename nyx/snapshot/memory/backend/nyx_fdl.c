#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/sysemu.h"

#include "exec/ram_addr.h"
#include "migration/migration.h"
#include "qemu/rcu_queue.h"

#include "nyx/memory_access.h"

#include <linux/kvm.h>
#include <sys/ioctl.h>

#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/backend/nyx_fdl.h"
#include "nyx/snapshot/memory/nyx_fdl_user.h"

/* debug option for the FDL constructor */
// #define DEBUG_VMX_FDL_ALLOC

/* additional output to debug the FDL restore operation */
// #define SHOW_NUM_DIRTY_PAGES

/* option to include restore of VRAM memory */
// #define RESET_VRAM
// #define DEBUG_FDL_VRAM

nyx_fdl_t *nyx_fdl_init(shadow_memory_t *shadow_memory)
{
    static bool fdl_created = false;
    /* not sure if we're able to create another FDL instance -> probably not */
    assert(fdl_created == false);
    fdl_created = true;

    nyx_fdl_t *self = malloc(sizeof(nyx_fdl_t));
    memset(self, 0, sizeof(nyx_fdl_t));

    int       ret;
    CPUState *cpu = qemu_get_cpu(0);
    kvm_cpu_synchronize_state(cpu);

    struct fdl_conf configuration;

    assert(kvm_state);
    self->vmx_fdl_fd = kvm_vm_ioctl(kvm_state, KVM_VMX_FDL_SETUP_FD, (unsigned long)0);

    configuration.num = 0;

    for (uint8_t i = 0; i < shadow_memory->ram_regions_num; i++) {
        configuration.areas[configuration.num].base_address =
            shadow_memory->ram_regions[i].base;
        configuration.areas[configuration.num].size =
            shadow_memory->ram_regions[i].size;
        configuration.num++;
    }

    ret = ioctl(self->vmx_fdl_fd, KVM_VMX_FDL_SET, &configuration);
    assert(ret == 0);

#ifdef DEBUG_VMX_FDL_ALLOC
    printf("KVM_VMX_FDL_SET: %d\n", ret);
    printf("configuration.mmap_size = 0x%lx\n", configuration.mmap_size);
    for (uint8_t i = 0; i < configuration.num; i++) {
        printf("configuration.areas[%d].mmap_bitmap_offset = 0x%lx\n", i,
               configuration.areas[i].mmap_bitmap_offset);
        printf("configuration.areas[%d].mmap_stack_offset = 0x%lx\n", i,
               configuration.areas[i].mmap_stack_offset);
    }
#endif

    self->vmx_fdl_mmap = mmap(NULL, configuration.mmap_size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, self->vmx_fdl_fd, 0);

    assert(self->vmx_fdl_mmap != (void *)0xFFFFFFFFFFFFFFFF);

    for (uint8_t i = 0; i < configuration.num; i++) {
        self->entry[i].stack =
            self->vmx_fdl_mmap + configuration.areas[i].mmap_stack_offset;
        self->entry[i].bitmap =
            self->vmx_fdl_mmap + configuration.areas[i].mmap_bitmap_offset;

#ifdef DEBUG_VMX_FDL_ALLOC
        printf("fdl_stacks[%d]  -> %p\n", i, self->entry[i].stack);
        printf("fdl_bitmaps[%d] -> %p\n", i, self->entry[i].bitmap);
#endif
    }

    self->num = configuration.num;

    struct fdl_result result;
    memset(&result, 0, sizeof(struct fdl_result));
    ret = ioctl(self->vmx_fdl_fd, KVM_VMX_FDL_GET_INDEX, &result);

#ifdef DEBUG_VMX_FDL_ALLOC
    printf("result: %d\n", result.num);
    for (uint8_t i = 0; i < result.num; i++) {
        printf("result.values[%d]: %ld\n", i, result.values[i]);
    }
#endif

    return self;
}

/* restore operation */
uint32_t nyx_snapshot_nyx_fdl_restore(nyx_fdl_t                 *self,
                                      shadow_memory_t           *shadow_memory_state,
                                      snapshot_page_blocklist_t *blocklist)
{
    uint32_t num_dirty_pages = 0;
    void    *current_region  = NULL;

    struct fdl_result result;
    memset(&result, 0, sizeof(struct fdl_result));
    int res = ioctl(self->vmx_fdl_fd, KVM_VMX_FDL_GET_INDEX, &result);
    assert(!res);

    // nyx_snapshot_nyx_fdl_unset_blocklisted_pages(self, shadow_memory_state, blocklist);

    for (uint8_t i = 0; i < result.num; i++) {
#ifdef SHOW_NUM_DIRTY_PAGES
        printf("Kernel -> [%d] %ld \t%ldKB\n", i, result.values[i],
               (0x1000 * result.values[i]) >> 0x10);
#endif

        if (shadow_memory_state->incremental_enabled) {
            current_region =
                shadow_memory_state->ram_regions[i].incremental_region_ptr;
        } else {
            current_region = shadow_memory_state->ram_regions[i].snapshot_region_ptr;
        }

        for (uint64_t j = 0; j < result.values[i]; j++) {
            uint64_t physical_addr = self->entry[i].stack[j];
            uint64_t entry_offset_addr =
                physical_addr - shadow_memory_state->ram_regions[i].base;

            void *host_addr = shadow_memory_state->ram_regions[i].host_region_ptr +
                              entry_offset_addr;
            void *snapshot_addr = current_region + entry_offset_addr;


            if (snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) ==
                true)
            {
#ifdef DEBUG_VERFIY_BITMAP
                if (!is_black_listed_addr(self, entry_offset_addr)) {
                    printf("WARNING: %s: -> %lx is not blacklisted\n", __func__,
                           entry_offset_addr);
                    abort();
                }
#endif
                continue; // blacklisted page
            }

            clear_bit(entry_offset_addr >> 12, (void *)self->entry[i].bitmap);
            memcpy(host_addr, snapshot_addr, TARGET_PAGE_SIZE);
            num_dirty_pages++;
        }
    }
#ifdef RESET_VRAM
    // nyx_snapshot_nyx_fdl_restore_vram(self, shadow_memory_state);
#endif
    return num_dirty_pages;
}

void nyx_snapshot_nyx_fdl_save_root_pages(nyx_fdl_t       *self,
                                          shadow_memory_t *shadow_memory_state,
                                          snapshot_page_blocklist_t *blocklist)
{
    struct fdl_result result;
    memset(&result, 0, sizeof(struct fdl_result));
    int res = ioctl(self->vmx_fdl_fd, KVM_VMX_FDL_GET_INDEX, &result);
    assert(!res);

    for (uint8_t i = 0; i < result.num; i++) {
#ifdef SHOW_NUM_DIRTY_PAGES
        printf("Kernel -> [%d] %ld \t%ldKB\n", i, result.values[i],
               (0x1000 * result.values[i]) >> 0x10);
#endif

        for (uint64_t j = 0; j < result.values[i]; j++) {
            uint64_t physical_addr = self->entry[i].stack[j];
            uint64_t entry_offset_addr =
                physical_addr - shadow_memory_state->ram_regions[i].base;

            void *host_addr = shadow_memory_state->ram_regions[i].host_region_ptr +
                              entry_offset_addr;
            void *incremental_addr =
                shadow_memory_state->ram_regions[i].incremental_region_ptr +
                entry_offset_addr;

            if (snapshot_page_blocklist_check_phys_addr(blocklist, physical_addr) ==
                true)
            {
#ifdef DEBUG_VERFIY_BITMAP
                if (!is_black_listed_addr(self, entry_offset_addr)) {
                    printf("WARNING: %s: -> %lx is not blacklisted\n", __func__,
                           entry_offset_addr);
                    abort();
                }
#endif
                continue; // skip blacklisted page
            }

            clear_bit(entry_offset_addr >> 12, (void *)self->entry[i].bitmap);
            shadow_memory_track_dirty_root_pages(shadow_memory_state,
                                                 entry_offset_addr, i);
            memcpy(incremental_addr, host_addr, TARGET_PAGE_SIZE);
        }
    }
}
