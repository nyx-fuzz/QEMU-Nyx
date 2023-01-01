
#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "sysemu/sysemu.h"

#include "exec/ram_addr.h"
#include "migration/migration.h"
#include "qemu/rcu_queue.h"

#include "nyx/debug.h"
#include "nyx/helpers.h"
#include "nyx/memory_access.h"

#include "nyx/snapshot/helper.h"
#include "nyx/snapshot/memory/shadow_memory.h"
#include "nyx/mem_split.h"

typedef struct fast_reload_dump_head_s {
    uint32_t shadow_memory_regions;
    uint32_t ram_region_index; // remove
} fast_reload_dump_head_t;

typedef struct fast_reload_dump_entry_s {
    uint64_t shadow_memory_offset;
    char     idstr[256];
} fast_reload_dump_entry_t;


static void shadow_memory_set_incremental_ptrs(shadow_memory_t *self)
{
    for (uint8_t i = 0; i < self->ram_regions_num; i++) {
        self->ram_regions[i].incremental_region_ptr =
            self->incremental_ptr + self->ram_regions[i].offset;
    }
}

static void shadow_memory_pre_alloc_incremental(shadow_memory_t *self)
{
    self->incremental_ptr = mmap(0, self->memory_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE, self->snapshot_ptr_fd, 0);
    shadow_memory_set_incremental_ptrs(self);
}

static void shadow_memory_init_generic(shadow_memory_t *self)
{
    self->root_track_pages_num  = 0;
    self->root_track_pages_size = 32 << 10;
    self->root_track_pages_stack =
        malloc(sizeof(uint64_t) * self->root_track_pages_size);
    shadow_memory_pre_alloc_incremental(self);

    self->incremental_enabled = false;
}

shadow_memory_t *shadow_memory_init(void)
{
    RAMBlock *block;
    RAMBlock *block_array[10];
    void     *snapshot_ptr_offset_array[10];

    shadow_memory_t *self = malloc(sizeof(shadow_memory_t));
    memset(self, 0x0, sizeof(shadow_memory_t));

    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        self->memory_size += block->used_length;
    }

    self->snapshot_ptr_fd =
        memfd_create("in_memory_root_snapshot", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    assert(!ftruncate(self->snapshot_ptr_fd, self->memory_size));
    fcntl(self->snapshot_ptr_fd, F_ADD_SEALS,
          F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL);

    self->snapshot_ptr = mmap(NULL, self->memory_size, PROT_READ | PROT_WRITE,
                              MAP_SHARED, self->snapshot_ptr_fd, 0);
    madvise(self->snapshot_ptr, self->memory_size, MADV_RANDOM | MADV_MERGEABLE);

    nyx_debug_p(RELOAD_PREFIX, "Allocating Memory (%p) Size: %lx\n",
                self->snapshot_ptr, self->memory_size);


    uint64_t offset      = 0;
    uint8_t  i           = 0;
    uint8_t  regions_num = 0;
    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        nyx_debug_p(RELOAD_PREFIX, "%lx %lx %lx\t%s\t%p\n", block->offset,
                    block->used_length, block->max_length, block->idstr, block->host);
        block_array[i] = block;

        memcpy(self->snapshot_ptr + offset, block->host, block->used_length);
        snapshot_ptr_offset_array[i++] = self->snapshot_ptr + offset;
        offset += block->used_length;
        regions_num++;
    }

    for (uint8_t i = 0; i < regions_num; i++) {
        block = block_array[i];
        if (!block->mr->readonly) {
            if (self->ram_regions_num == 0 && block->used_length >= get_mem_split_start()) {
                self->ram_regions[self->ram_regions_num].ram_region = i;
                self->ram_regions[self->ram_regions_num].base = block->mr->addr;
                self->ram_regions[self->ram_regions_num].size = get_mem_split_start();
                self->ram_regions[self->ram_regions_num].offset =
                    snapshot_ptr_offset_array[i] - snapshot_ptr_offset_array[0];
                self->ram_regions[self->ram_regions_num].host_region_ptr = block->host;
                self->ram_regions[self->ram_regions_num].snapshot_region_ptr =
                    self->snapshot_ptr +
                    self->ram_regions[self->ram_regions_num].offset;
                self->ram_regions[self->ram_regions_num].idstr =
                    malloc(strlen(block->idstr) + 1);
                memset(self->ram_regions[self->ram_regions_num].idstr, 0,
                       strlen(block->idstr) + 1);
                strcpy(self->ram_regions[self->ram_regions_num].idstr, block->idstr);
                self->ram_regions_num++;

                self->ram_regions[self->ram_regions_num].ram_region = i;
                self->ram_regions[self->ram_regions_num].base = get_mem_split_end();
self->ram_regions[self->ram_regions_num].size = block->used_length - get_mem_split_start();
self->ram_regions[self->ram_regions_num].offset =
    (snapshot_ptr_offset_array[i] + get_mem_split_start()) - snapshot_ptr_offset_array[0];
self->ram_regions[self->ram_regions_num].host_region_ptr =
    block->host + get_mem_split_start();
self->ram_regions[self->ram_regions_num].snapshot_region_ptr =
    snapshot_ptr_offset_array[i] + get_mem_split_start();
self->ram_regions[self->ram_regions_num].idstr = malloc(strlen(block->idstr) + 1);
memset(self->ram_regions[self->ram_regions_num].idstr, 0, strlen(block->idstr) + 1);
strcpy(self->ram_regions[self->ram_regions_num].idstr, block->idstr);
}
else {
    self->ram_regions[self->ram_regions_num].ram_region = i;
    self->ram_regions[self->ram_regions_num].base       = block->mr->addr;
    self->ram_regions[self->ram_regions_num].size       = block->used_length;
    self->ram_regions[self->ram_regions_num].offset =
        snapshot_ptr_offset_array[i] - snapshot_ptr_offset_array[0];
    self->ram_regions[self->ram_regions_num].host_region_ptr = block->host;
    self->ram_regions[self->ram_regions_num].snapshot_region_ptr =
        self->snapshot_ptr + self->ram_regions[self->ram_regions_num].offset;
    self->ram_regions[self->ram_regions_num].idstr = malloc(strlen(block->idstr) + 1);
    memset(self->ram_regions[self->ram_regions_num].idstr, 0,
           strlen(block->idstr) + 1);
    strcpy(self->ram_regions[self->ram_regions_num].idstr, block->idstr);
}

self->ram_regions_num++;
}
}


shadow_memory_init_generic(self);
return self;
}

shadow_memory_t *shadow_memory_init_from_snapshot(const char *snapshot_folder,
                                                  bool        pre_snapshot)
{
    RAMBlock *block;
    RAMBlock *block_array[10];
    void     *snapshot_ptr_offset_array[10];

    shadow_memory_t *self = malloc(sizeof(shadow_memory_t));
    memset(self, 0x0, sizeof(shadow_memory_t));

    /* count total memory size */
    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        self->memory_size += block->used_length;
    }

    /* count number of ram regions */
    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        if (!block->mr->readonly) {
            if (self->ram_regions_num == 0 && block->used_length >= get_mem_split_start()) {
                self->ram_regions_num++;
            }
            self->ram_regions_num++;
        }
    }

    char *path_meta;
    char *path_dump;
    assert(asprintf(&path_meta, "%s/fast_snapshot.mem_meta", snapshot_folder) != -1);
    assert(asprintf(&path_dump, "%s/fast_snapshot.mem_dump", snapshot_folder) != -1);

    fast_reload_dump_head_t head;

    FILE *file_mem_meta = fopen(path_meta, "r");
    assert(file_mem_meta != NULL);
    assert(fread(&head, sizeof(fast_reload_dump_head_t), 1, file_mem_meta) == 1);
    fclose(file_mem_meta);

    assert(self->ram_regions_num == head.shadow_memory_regions);
    // printf("LOAD -> self->ram_regions_num: %d\n", self->ram_regions_num);

    FILE *file_mem_dump = fopen(path_dump, "r");
    assert(file_mem_dump != NULL);
    fseek(file_mem_dump, 0L, SEEK_END);
    uint64_t file_mem_dump_size = ftell(file_mem_dump);

    nyx_debug("guest_ram_size == ftell(f) => 0x%lx vs 0x%lx (%s)\n",
              self->memory_size, file_mem_dump_size, path_dump);

#define VGA_SIZE (16 << 20)

    if (self->memory_size != file_mem_dump_size) {
        if (file_mem_dump_size >= VGA_SIZE) {
            nyx_abort("Guest size should be %ld MB - set it to %ld MB\n",
                      (file_mem_dump_size - VGA_SIZE) >> 20,
                      (self->memory_size - VGA_SIZE) >> 20);
        } else {
            nyx_abort("Guest mem size != file size: %ld != %ld bytes\n",
                      self->memory_size, file_mem_dump_size);
        }
    }
    assert(self->memory_size == ftell(file_mem_dump));
    fseek(file_mem_dump, 0L, SEEK_SET);
    fclose(file_mem_dump);

    self->snapshot_ptr_fd = open(path_dump, O_RDONLY);
    self->snapshot_ptr =
        mmap(0, self->memory_size, PROT_READ, MAP_SHARED, self->snapshot_ptr_fd, 0);

    assert(self->snapshot_ptr != (void *)-1);
    madvise(self->snapshot_ptr, self->memory_size, MADV_MERGEABLE);


    uint64_t offset      = 0;
    uint8_t  i           = 0;
    uint8_t  regions_num = 0;
    QLIST_FOREACH_RCU (block, &ram_list.blocks, next) {
        nyx_debug_p(RELOAD_PREFIX, "%lx %lx %lx\t%s\t%p\n", block->offset,
                    block->used_length, block->max_length, block->idstr, block->host);

        block_array[i]                 = block;
        snapshot_ptr_offset_array[i++] = self->snapshot_ptr + offset;
        offset += block->used_length;
        regions_num++;
    }

    self->ram_regions_num = 0;
    for (uint8_t i = 0; i < regions_num; i++) {
        block = block_array[i];
        if (!block->mr->readonly) {
            if (self->ram_regions_num == 0 && block->used_length >= get_mem_split_start()) {
                self->ram_regions[self->ram_regions_num].ram_region = i;
                self->ram_regions[self->ram_regions_num].base = block->mr->addr;
                self->ram_regions[self->ram_regions_num].size = get_mem_split_start();
                self->ram_regions[self->ram_regions_num].offset =
                    snapshot_ptr_offset_array[i] - snapshot_ptr_offset_array[0];
                self->ram_regions[self->ram_regions_num].host_region_ptr = block->host;
                self->ram_regions[self->ram_regions_num].snapshot_region_ptr =
                    self->snapshot_ptr +
                    self->ram_regions[self->ram_regions_num].offset;
                self->ram_regions[self->ram_regions_num].idstr =
                    malloc(strlen(block->idstr) + 1);
                memset(self->ram_regions[self->ram_regions_num].idstr, 0,
                       strlen(block->idstr) + 1);
                strcpy(self->ram_regions[self->ram_regions_num].idstr, block->idstr);
                self->ram_regions_num++;

                self->ram_regions[self->ram_regions_num].ram_region = i;
                self->ram_regions[self->ram_regions_num].base = get_mem_split_end();
self->ram_regions[self->ram_regions_num].size = block->used_length - get_mem_split_start();
self->ram_regions[self->ram_regions_num].offset =
    (snapshot_ptr_offset_array[i] + get_mem_split_start()) - snapshot_ptr_offset_array[0];
self->ram_regions[self->ram_regions_num].host_region_ptr =
    block->host + get_mem_split_start();
self->ram_regions[self->ram_regions_num].snapshot_region_ptr =
    snapshot_ptr_offset_array[i] + get_mem_split_start();
self->ram_regions[self->ram_regions_num].idstr = malloc(strlen(block->idstr) + 1);
memset(self->ram_regions[self->ram_regions_num].idstr, 0, strlen(block->idstr) + 1);
strcpy(self->ram_regions[self->ram_regions_num].idstr, block->idstr);
}
else {
    self->ram_regions[self->ram_regions_num].ram_region = i;
    self->ram_regions[self->ram_regions_num].base       = block->mr->addr;
    self->ram_regions[self->ram_regions_num].size       = block->used_length;
    self->ram_regions[self->ram_regions_num].offset =
        snapshot_ptr_offset_array[i] - snapshot_ptr_offset_array[0];
    self->ram_regions[self->ram_regions_num].host_region_ptr = block->host;
    self->ram_regions[self->ram_regions_num].snapshot_region_ptr =
        self->snapshot_ptr + self->ram_regions[self->ram_regions_num].offset;
    self->ram_regions[self->ram_regions_num].idstr = malloc(strlen(block->idstr) + 1);
    memset(self->ram_regions[self->ram_regions_num].idstr, 0,
           strlen(block->idstr) + 1);
    strcpy(self->ram_regions[self->ram_regions_num].idstr, block->idstr);
}

self->ram_regions_num++;
}
}

#ifdef DEBUG_SHADOW_MEMCPY_VERSION
/* memcpy version */
for (uint8_t i = 0; i < self->ram_regions_num; i++) {
    void *host_addr     = self->ram_regions[i].host_region_ptr + 0;
    void *snapshot_addr = self->ram_regions[i].snapshot_region_ptr + 0;
    memcpy(host_addr, snapshot_addr, self->ram_regions[i].size);
}
#else
/* munmap + mmap version */
for (uint8_t i = 0; i < self->ram_regions_num; i++) {
    void *host_addr = self->ram_regions[i].host_region_ptr + 0;
    assert(munmap(host_addr, self->ram_regions[i].size) != EINVAL);
    assert(mmap(host_addr, self->ram_regions[i].size,
                PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED,
                self->snapshot_ptr_fd, self->ram_regions[i].offset) != MAP_FAILED);
}
#endif

shadow_memory_init_generic(self);
return self;
}


void shadow_memory_prepare_incremental(shadow_memory_t *self)
{
    static int count = 0;

    if (count >= RESTORE_RATE) {
        count = 0;
        munmap(self->incremental_ptr, self->memory_size);
        self->incremental_ptr = mmap(0, self->memory_size, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE, self->snapshot_ptr_fd, 0);
        shadow_memory_set_incremental_ptrs(self);
    }
    count++;
}

void shadow_memory_switch_snapshot(shadow_memory_t *self, bool incremental)
{
    self->incremental_enabled = incremental;
}

void shadow_memory_restore_memory(shadow_memory_t *self)
{
    rcu_read_lock();

    uint8_t  slot = 0;
    uint64_t addr = 0;
    for (uint64_t i = 0; i < self->root_track_pages_num; i++) {
        addr = self->root_track_pages_stack[i] & 0xFFFFFFFFFFFFF000;
        slot = self->root_track_pages_stack[i] & 0xFFF;

        memcpy(self->ram_regions[slot].host_region_ptr + addr,
               self->ram_regions[slot].snapshot_region_ptr + addr, TARGET_PAGE_SIZE);
        memcpy(self->ram_regions[slot].incremental_region_ptr + addr,
               self->ram_regions[slot].snapshot_region_ptr + addr, TARGET_PAGE_SIZE);
    }

    self->root_track_pages_num = 0;
    rcu_read_unlock();
}


/* only used in debug mode -> no need to be fast */
bool shadow_memory_is_root_page_tracked(shadow_memory_t *self,
                                        uint64_t         address,
                                        uint8_t          slot)
{
    uint64_t value = (address & 0xFFFFFFFFFFFFF000) | slot;

    for (uint64_t i = 0; i < self->root_track_pages_num; i++) {
        if (self->root_track_pages_stack[i] == value) {
            return true;
        }
    }
    return false;
}

void shadow_memory_serialize(shadow_memory_t *self, const char *snapshot_folder)
{
    char *tmp1;
    char *tmp2;
    assert(asprintf(&tmp1, "%s/fast_snapshot.mem_meta", snapshot_folder) != -1);
    assert(asprintf(&tmp2, "%s/fast_snapshot.mem_dump", snapshot_folder) != -1);

    FILE *file_mem_meta = fopen(tmp1, "w+b");
    FILE *file_mem_data = fopen(tmp2, "w+b");

    fast_reload_dump_head_t  head;
    fast_reload_dump_entry_t entry;

    head.shadow_memory_regions = self->ram_regions_num;
    head.ram_region_index      = 0; /* due to legacy reasons */

    fwrite(&head, sizeof(fast_reload_dump_head_t), 1, file_mem_meta);

    for (uint64_t i = 0; i < self->ram_regions_num; i++) {
        memset(&entry, 0x0, sizeof(fast_reload_dump_entry_t));
        entry.shadow_memory_offset = (uint64_t)self->ram_regions[i].offset;
        strncpy((char *)&entry.idstr, (const char *)self->ram_regions[i].idstr, 255);
        fwrite(&entry, sizeof(fast_reload_dump_entry_t), 1, file_mem_meta);
    }

    fwrite(self->snapshot_ptr, self->memory_size, 1, file_mem_data);

    fclose(file_mem_meta);
    fclose(file_mem_data);
}

static bool shadow_memory_read_page_frame(shadow_memory_t *self,
                                          uint64_t         address,
                                          void            *ptr,
                                          uint16_t         offset,
                                          uint16_t         size)
{
    assert((offset + size) <= 0x1000);

    for (uint8_t i = 0; i < self->ram_regions_num; i++) {
        if (address >= self->ram_regions[i].base &&
            address < (self->ram_regions[i].base + self->ram_regions[i].size))
        {
            void *snapshot_ptr = self->ram_regions[i].snapshot_region_ptr +
                                 (address - self->ram_regions[i].base);
            memcpy(ptr, snapshot_ptr + offset, size);
            return true;
        }
    }
    return false;
}

bool shadow_memory_read_physical_memory(shadow_memory_t *self,
                                        uint64_t         address,
                                        void            *ptr,
                                        size_t           size)
{
    size_t   bytes_left      = size;
    size_t   copy_bytes      = 0;
    uint64_t current_address = address;
    uint64_t offset          = 0;

    while (bytes_left != 0) {
        /* full page */
        if ((current_address & 0xFFF) == 0) {
            copy_bytes = 0x1000;
        }
        /* partial page (starting at an offset) */
        else
        {
            copy_bytes = 0x1000 - (current_address & 0xFFF);
        }

        /* partial page */
        if (bytes_left < copy_bytes) {
            copy_bytes = bytes_left;
        }

        if (shadow_memory_read_page_frame(self, current_address & ~0xFFFULL,
                                          ptr + offset, current_address & 0xFFFULL,
                                          copy_bytes) == false)
        {
            return false;
        }
        current_address += copy_bytes;
        offset += copy_bytes;
        bytes_left = bytes_left - copy_bytes;
    }
    return true;
}
