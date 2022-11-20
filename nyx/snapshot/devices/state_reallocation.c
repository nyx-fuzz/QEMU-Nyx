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

#include "qemu/main-loop.h"
#include "sysemu/sysemu.h"

#include "migration/qemu-file.h"
#include "migration/register.h"
#include "migration/savevm.h"
#include "migration/vmstate.h"
#include "sysemu/kvm_int.h"

#include "nyx/debug.h"
#include "nyx/snapshot/devices/nyx_device_state.h"
#include "nyx/snapshot/devices/state_reallocation.h"

// #define VERBOSE_DEBUG

#define QEMU_VM_SUBSECTION 0x05

typedef struct CompatEntry {
    char idstr[256];
    int  instance_id;
} CompatEntry;

typedef struct SaveStateEntry {
    QTAILQ_ENTRY(SaveStateEntry) entry;
    char                      idstr[256];
    int                       instance_id;
    int                       alias_id;
    int                       version_id;
    int                       load_version_id;
    int                       section_id;
    int                       load_section_id;
    SaveVMHandlers           *ops;
    const VMStateDescription *vmsd;
    CompatEntry              *opaque;
    CompatEntry              *compat;
    int                       is_ram;
} SaveStateEntry;

struct LoadStateEntry {
    QLIST_ENTRY(LoadStateEntry) entry;
    SaveStateEntry *se;
    int             section_id;
    int             version_id;
};

typedef struct SaveState {
    QTAILQ_HEAD(, SaveStateEntry) handlers;
    int         global_section_id;
    bool        skip_configuration;
    uint32_t    len;
    const char *name;
    uint32_t    target_page_bits;
} SaveState;

extern void     *vmstate_configuration;
extern SaveState savevm_state;

extern int  vmstate_n_elems(void *opaque, VMStateField *field);
extern int  vmstate_size(void *opaque, VMStateField *field);
extern void vmstate_handle_alloc(void *ptr, VMStateField *field, void *opaque);
extern int  vmstate_load(QEMUFile *f, SaveStateEntry *se);

static void fast_timer_get(void *data, size_t size, void *opaque)
{
    QEMUTimer *ts          = (QEMUTimer *)opaque;
    uint64_t   expire_time = *((uint64_t *)data);
    if (expire_time != -1) {
        timer_mod_ns(ts, expire_time);
    } else {
        timer_del(ts);
    }
}

static SaveStateEntry *fdl_find_se(const char *idstr, int instance_id)
{
    SaveStateEntry *se;

    QTAILQ_FOREACH (se, &savevm_state.handlers, entry) {
        if (!strcmp(se->idstr, idstr) &&
            (instance_id == se->instance_id || instance_id == se->alias_id))
        {
            return se;
        }
        /* Migrating from an older version? */
        if (strstr(se->idstr, idstr) && se->compat) {
            if (!strcmp(se->compat->idstr, idstr) &&
                (instance_id == se->compat->instance_id || instance_id == se->alias_id))
            {
                return se;
            }
        }
    }
    return NULL;
}

static int fdl_vmstate_load_state(state_reallocation_t     *self,
                                  QEMUFile                 *f,
                                  const VMStateDescription *vmsd,
                                  void                     *opaque,
                                  int                       version_id,
                                  uintptr_t                *opaque_ptr);


static inline VMStateDescription *fdl_vmstate_get_subsection(VMStateDescription **sub,
                                                             char *idstr)
{
    while (sub && *sub && (*sub)->needed) {
        if (strcmp(idstr, (*sub)->name) == 0) {
            return *sub;
        }
        sub++;
    }
    return NULL;
}

static int fdl_vmstate_subsection_load(state_reallocation_t     *self,
                                       QEMUFile                 *f,
                                       const VMStateDescription *vmsd,
                                       void                     *opaque)
{
    while (qemu_peek_byte(f, 0) == QEMU_VM_SUBSECTION) {
        char                      idstr[256], *idstr_ret;
        int                       ret;
        uint8_t                   version_id, len, size;
        const VMStateDescription *sub_vmsd;

        len = qemu_peek_byte(f, 1);
        if (len < strlen(vmsd->name) + 1) {
            /* subsection name has to be "section_name/a" */
            return 0;
        }
        size = qemu_peek_buffer(f, (uint8_t **)&idstr_ret, len, 2);
        if (size != len) {
            return 0;
        }
        memcpy(idstr, idstr_ret, size);
        idstr[size] = 0;

        if (strncmp(vmsd->name, idstr, strlen(vmsd->name)) != 0) {
            /* it doesn't have a valid subsection name */
            return 0;
        }
        sub_vmsd = fdl_vmstate_get_subsection((VMStateDescription **)vmsd->subsections,
                                              idstr);
        if (sub_vmsd == NULL) {
            return -ENOENT;
        }
        qemu_file_skip(f, 1);   /* subsection */
        qemu_file_skip(f, 1);   /* len */
        qemu_file_skip(f, len); /* idstr */
        version_id = qemu_get_be32(f);

        ret = fdl_vmstate_load_state(self, f, sub_vmsd, opaque, version_id, NULL);
        if (ret) {
            return ret;
        }
    }

    return 0;
}

uint32_t post_counter = 0;
void    *post_fptr_array[256];
uint32_t post_version_id_array[256];
void    *post_opaque_array[256];


static void add_post_fptr(state_reallocation_t *self,
                          void                 *fptr,
                          uint32_t              version_id,
                          void                 *opaque,
                          const char           *name)
{
    if (!self) {
        return;
    }

    if (!strcmp("I440FX", name)) {
        return;
    }


    if (1) {
        /*
        if( !strcmp("cpu_common", name) ||
            !strcmp("cpu/nested_state", name) ||
            !strcmp("cpu", name) ||
            //!strcmp("kvm-tpr-opt", name) ||

            !strcmp("globalstate", name) ||
            !strcmp("serial", name) ||

            !strcmp("i8259", name) ||
            !strcmp("i8254", name) ||

            !strcmp("apic", name) ||
            //!strcmp("vga", name) ||
            //!strcmp("ide", name) ||
            //!strcmp("ide_drive", name) ||
            !strcmp("ioapic", name)){
        */

        /*
        --> cpu_common
        --> cpu/nested_state
        --> cpu
        --> apic
        --> I440FX
        --> PIIX3
        --> i8259
        --> i8259
        --> ioapic
        --> vga
        --> hpet
        --> mc146818rtc
        --> i8254
        --> dma
        --> dma
        --> serial
        --> fdrive
        --> fdrive
        --> fdc
        --> ps2kbd
        --> ps2mouse
        --> pckbd
        --> vmmouse
        --> e1000/tx_tso_state
        --> e1000
        --> ide_drive
        --> ide_drive
        --> ide_drive
        --> ide_drive
        --> ide
        --> piix4_pm
        --> globalstate
        */

        // printf("--> %s\n", name);

        self->fptr[self->fast_state_fptr_pos]    = fptr;
        self->opaque[self->fast_state_fptr_pos]  = opaque;
        self->version[self->fast_state_fptr_pos] = version_id;
        self->fast_state_fptr_pos++;

        if (self->fast_state_fptr_pos >= self->fast_state_fptr_size) {
            nyx_debug("RESIZE %s\n", __func__);
            self->fast_state_fptr_size += REALLOC_SIZE;
            self->fptr =
                realloc(self->fptr, self->fast_state_fptr_size * sizeof(void *));
            self->opaque =
                realloc(self->opaque, self->fast_state_fptr_size * sizeof(void *));
            self->version =
                realloc(self->version, self->fast_state_fptr_size * sizeof(uint32_t));
        }
    }
}

extern void fast_get_pci_config_device(void *data, size_t size, void *opaque);
void        fast_get_pci_irq_state(void *data, size_t size, void *opaque);

// void fast_virtio_device_get(void* data, size_t size, void* opaque);
int virtio_device_get(QEMUFile *f, void *opaque, size_t size, const VMStateField *field);

static int fast_loadvm_fclose(void *opaque)
{
    return 0;
}

static ssize_t fast_loadvm_get_buffer(void *opaque, uint8_t *buf, int64_t pos, size_t size)
{
    assert(pos < ((struct fast_savevm_opaque_t *)(opaque))->buflen);
    memcpy(buf, (void *)(((struct fast_savevm_opaque_t *)(opaque))->buf + pos), size);
    return size;
}

static const QEMUFileOps fast_loadvm_ops = {
    .get_buffer = (QEMUFileGetBufferFunc *)fast_loadvm_get_buffer,
    .close      = (QEMUFileCloseFunc *)fast_loadvm_fclose
};

/* use opaque data to bootstrap virtio restore from QEMUFile */
static void fast_virtio_device_get(void *data, size_t size, void *opaque)
{
    struct fast_savevm_opaque_t fast_loadvm_opaque = {
        .buf    = data,
        .buflen = size,
        .f      = NULL,
        .pos    = 0,
    };
    QEMUFile *f = qemu_fopen_ops(&fast_loadvm_opaque, &fast_loadvm_ops);

    virtio_device_get(f, opaque, size, NULL);
}

static void add_get(state_reallocation_t *self,
                    void                 *fptr,
                    void                 *opaque,
                    size_t                size,
                    void                 *field,
                    QEMUFile             *f,
                    const char           *name)
{
    if (!self) {
        return;
    }

    void (*handler)(void *, size_t, void *) = NULL;
    uint8_t *data                           = NULL;

    if (!strcmp(name, "timer")) {
        nyx_debug("SKPPING: %ld\n", size * -1);
        qemu_file_skip(f, size * -1);
        handler             = fast_timer_get;
        data                = malloc(sizeof(uint64_t));
        *((uint64_t *)data) = qemu_get_be64(f);
    }

    else if (!strcmp(name, "pci irq state"))
    {
        qemu_file_skip(f, size * -1);
        handler = fast_get_pci_irq_state;
        data    = malloc(sizeof(uint8_t) * size);

        ((uint32_t *)data)[0] = qemu_get_be32(f);
        ((uint32_t *)data)[1] = qemu_get_be32(f);
        ((uint32_t *)data)[2] = qemu_get_be32(f);
        ((uint32_t *)data)[3] = qemu_get_be32(f);
    } else if (!strcmp(name, "pci config")) {
        qemu_file_skip(f, size * -1);
        handler = fast_get_pci_config_device;
        data    = malloc(sizeof(uint8_t) * size);
        qemu_get_buffer(f, (uint8_t *)data, size);
    } else if (!strcmp(name, "virtio")) {
        qemu_file_skip(f, size * -1);
        handler = fast_virtio_device_get;
        data    = malloc(sizeof(uint8_t) * size);
        qemu_get_buffer(f, (uint8_t *)data, size);
    } else {
        nyx_warn("NOT IMPLEMENTED FAST GET ROUTINE for %s\n", name);
        abort();
        return;
    }

    // will be called by pre-/post-save or pre-post-load?
    // will be processed by fdl_fast_reload()
    self->get_fptr[self->fast_state_get_fptr_pos]   = handler;
    self->get_opaque[self->fast_state_get_fptr_pos] = opaque;
    self->get_size[self->fast_state_get_fptr_pos]   = size;
    self->get_data[self->fast_state_get_fptr_pos]   = data;

    self->fast_state_get_fptr_pos++;

    if (self->fast_state_get_fptr_pos >= self->fast_state_get_fptr_size) {
        nyx_debug("RESIZE %s\n", __func__);
        self->fast_state_get_fptr_size += REALLOC_SIZE;
        self->get_fptr =
            realloc(self->get_fptr, self->fast_state_get_fptr_size * sizeof(void *));
        self->get_opaque = realloc(self->get_opaque,
                                   self->fast_state_get_fptr_size * sizeof(void *));
        self->get_size =
            realloc(self->get_size, self->fast_state_get_fptr_size * sizeof(size_t));
        self->get_data =
            realloc(self->get_data, self->fast_state_get_fptr_size * sizeof(void *));
    }
}

static void add_mblock(state_reallocation_t *self,
                       char                 *foo,
                       const char           *bar,
                       size_t                offset,
                       uint64_t              start,
                       uint64_t              size)
{
    if (!self) {
        return;
    }

    if (self->fast_state_pos &&
        (uint64_t)(self->ptr[self->fast_state_pos - 1] +
                   self->size[self->fast_state_pos - 1]) == start)
    {
        void *new = (void *)(self->pre_alloc_block + self->pre_alloc_block_offset);
        self->pre_alloc_block_offset += size;
        memcpy(new, (void *)start, size);

        self->size[self->fast_state_pos - 1] =
            size + self->size[self->fast_state_pos - 1];
    } else {
        self->ptr[self->fast_state_pos] = (void *)start;
        self->copy[self->fast_state_pos] =
            (void *)(self->pre_alloc_block + self->pre_alloc_block_offset);
        self->pre_alloc_block_offset += size;

        memcpy(self->copy[self->fast_state_pos], (void *)start, size);
        self->size[self->fast_state_pos] = size;
        self->fast_state_pos++;
        if (self->fast_state_pos >= self->fast_state_size) {
            self->fast_state_size += REALLOC_SIZE;
            self->ptr  = realloc(self->ptr, self->fast_state_size * sizeof(void *));
            self->copy = realloc(self->copy, self->fast_state_size * sizeof(void *));
            self->size = realloc(self->size, self->fast_state_size * sizeof(size_t));
        }
    }
}

static inline int get_handler(state_reallocation_t *self,
                              QEMUFile             *f,
                              void                 *curr_elem,
                              size_t                size,
                              VMStateField         *field,
                              char                 *vmsd_name)
{
    int ret;
#ifdef VERBOSE_DEBUG
    nyx_debug("%s: %s\n", __func__, vmsd_name);
#endif

    ret = field->info->get(f, curr_elem, size, field);


    if (!strcmp(field->info->name, "bool")) {
        assert(size == 1);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   1);
    } else if (!strcmp(field->info->name, "int8")) {
        assert(size == 1);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   1);
    } else if (!strcmp(field->info->name, "int16")) {
        assert(size == 2);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   2);
    } else if (!strcmp(field->info->name, "int32")) {
        assert(size == 4);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   4);
    } else if (!strcmp(field->info->name, "int32 equal")) {
        assert(size == 4);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   4);
    } else if (!strcmp(field->info->name, "int32 le")) {
        assert(size == 4);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   4);
    } else if (!strcmp(field->info->name, "int64")) {
        assert(size == 8);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   8);
    } else if (!strcmp(field->info->name, "uint8")) {
        assert(size == 1);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   1);
    } else if (!strcmp(field->info->name, "uint16")) {
        assert(size == 2);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   2);
    } else if (!strcmp(field->info->name, "uint32")) {
        assert(size == 4);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   4);
    } else if (!strcmp(field->info->name, "uint32 equal")) {
        assert(size == 4);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   4);
    } else if (!strcmp(field->info->name, "uint64")) {
        assert(size == 8);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   8);
    } else if (!strcmp(field->info->name, "int64 equal")) {
        assert(size == 8);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   8);
    } else if (!strcmp(field->info->name, "uint8 equal")) {
        assert(size == 1);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   1);
    } else if (!strcmp(field->info->name, "uint16 equal")) {
        assert(size == 16);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   2);
    } else if (!strcmp(field->info->name, "float64")) {
        assert(size == 64);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   8);
    } else if (!strcmp(field->info->name, "CPU_Double_U")) {
        assert(0);
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   8);
    } else if (!strcmp(field->info->name, "buffer")) {
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   size);
    } else if (!strcmp(field->info->name, "unused_buffer")) {
        /* save nothing */
    } else if (!strcmp(field->info->name, "tmp")) {
        add_mblock(self, vmsd_name, field->name, field->offset, (uint64_t)curr_elem,
                   size);
        /* save nothing */
    } else if (!strcmp(field->info->name, "bitmap")) {
        assert(0);
    } else if (!strcmp(field->info->name, "qtailq")) {
        assert(0);
    } else if (!strcmp(field->info->name, "timer")) {
        add_get(self, (void *)field->info->get, curr_elem, size, (void *)field, f,
                field->info->name);
    } else if (!strcmp(field->info->name, "fpreg")) {
        nyx_debug("type: %s (size: %lx)\n", field->info->name, size);
        assert(0);
        add_get(self, (void *)field->info->get, curr_elem, size, (void *)field, f,
                field->info->name);
    } else if (!strcmp(field->info->name, "pci config")) {
        add_get(self, (void *)field->info->get, curr_elem, size, (void *)field, f,
                field->info->name);
    } else if (!strcmp(field->info->name, "pci irq state")) {
        add_get(self, (void *)field->info->get, curr_elem, size, (void *)field, f,
                field->info->name);
    } else if (!strcmp(field->info->name, "virtio")) {
        add_get(self, (void *)field->info->get, curr_elem, size, (void *)field, f,
                field->info->name);
    } else {
        nyx_error("%s: no handler for %s, type %s, size %lx!\n", __func__, vmsd_name,
                  field->info->name, size);
        assert(0);
    }
    return ret;
}

/* TODO: modify opaque_ptr */
static int fdl_vmstate_load_state(state_reallocation_t     *self,
                                  QEMUFile                 *f,
                                  const VMStateDescription *vmsd,
                                  void                     *opaque,
                                  int                       version_id,
                                  uintptr_t                *opaque_ptr)
{
#ifdef VERBOSE_DEBUG
    nyx_debug("---------------------------------\n"
              "VMSD: %p\t%s\n",
              opaque, vmsd->name);
#endif

    VMStateField *field = (VMStateField *)vmsd->fields;
    int           ret   = 0;

    uint64_t total_size = 0;

    if (version_id > vmsd->version_id) {
        return -EINVAL;
    }
    if (version_id < vmsd->minimum_version_id) {
#ifdef VERBOSE_DEBUG
        nyx_debug("OLD LOAD\n");
#endif

        if (vmsd->load_state_old && version_id >= vmsd->minimum_version_id_old) {
            nyx_debug("OLDSTATE\n");
            assert(0);
            ret = vmsd->load_state_old(f, opaque, version_id);
            return ret;
        }
        return -EINVAL;
    }
    if (vmsd->pre_load) {
#ifdef VERBOSE_DEBUG
        nyx_debug("\tPRELOAD Function\n");
#endif
        /* TODO ADD PRE FPTR FOR SERIAL */
        // nyx_debug("PRELOAD RUN: %s\n", vmsd->name);
        // add_pre_fptr(self, vmsd->pre_load, opaque, vmsd->name);
        add_post_fptr(self, vmsd->pre_load, 1337, opaque, vmsd->name);
    }
    while (field->name) {
#ifdef VERBOSE_DEBUG
        nyx_debug("Field: %s %s %s\n", __func__, vmsd->name, field->name);
#endif
        if ((field->field_exists && field->field_exists(opaque, version_id)) ||
            (!field->field_exists && field->version_id <= version_id))
        {
            void *first_elem = opaque + field->offset;
            int   i, n_elems = vmstate_n_elems(opaque, field);
            int   size = vmstate_size(opaque, field);

#ifdef VERBOSE_DEBUG
            nyx_debug("--> vmstate_handle_alloc\n");
#endif
            vmstate_handle_alloc(first_elem, field, opaque);
            if (field->flags & VMS_POINTER) {
#ifdef VERBOSE_DEBUG
                nyx_debug("FIX ME VMS_POINTER\n");
#endif
                // nyx_debug("Field-Offset 0x%lx-0x%lx\n",
                //           opaque+field->offset,
                //           opaque+field->offset+(size*n_elems));

                first_elem = *(void **)first_elem;
                assert(first_elem || !n_elems || !size);
            }

            for (i = 0; i < n_elems; i++) {
                uint64_t *tmp_opaque_ptr = 0;
                total_size += size;
                void *curr_elem = first_elem + size * i;

                if (field->flags & VMS_ARRAY_OF_POINTER) {
#ifdef VERBOSE_DEBUG
                    nyx_debug("Field-Offset 1 0x%lx-0x%lx\n",
                              (uint64_t)(field->offset + (opaque)),
                              (uint64_t)(field->offset + (size * n_elems) + (opaque)));
                    nyx_debug("=VMS_ARRAY_OF_POINTER 1= %lx %x\n",
                              *((uint64_t *)curr_elem), size);
                    // hexDump((void*)field->name, curr_elem, size);
#endif

                    tmp_opaque_ptr = curr_elem;
                    curr_elem      = *(void **)curr_elem;
                    add_mblock(self, (char *)vmsd->name, (const char *)field->name,
                               field->offset, (uint64_t)(curr_elem), (uint64_t)(size));
#ifdef VERBOSE_DEBUG
                    // hexDump((void*)field->name, curr_elem, size);
#endif
                }

                if (!curr_elem && size) {
                    // if null pointer check placeholder and do not follow
                    assert(field->flags & VMS_ARRAY_OF_POINTER);
#ifdef VERBOSE_DEBUG
                    nyx_debug("Field-Offset 2 0x%lx-0x%lx\n",
                              (uint64_t)(field->offset + (opaque)),
                              (uint64_t)(field->offset + (size * n_elems) + (opaque)));
                    nyx_debug("=VMS_ARRAY_OF_POINTER 2= %lx %x\n",
                              *((uint64_t *)curr_elem), size);
                    // hexDump((void*)field->name, curr_elem, size);
#endif

                    nyx_debug("*** vmstate_info_nullptr.get ***\n");
                    ret = vmstate_info_nullptr.get(f, curr_elem, size, NULL);
                    add_mblock(self, (char *)vmsd->name, (const char *)field->name,
                               field->offset, (uint64_t)(curr_elem), (uint64_t)(size));
#ifdef VERBOSE_DEBUG
                    // hexDump((void*)field->name, curr_elem, size);
#endif

                } else if (field->flags & VMS_STRUCT) {
                    // nyx_debug("Field-Offset 0x%lx-0x%lx\n",
                    // field->offset + (opaque-base_opaque),
                    // field->offset+(size*n_elems) + (opaque-base_opaque));
#ifdef VERBOSE_DEBUG
                    nyx_debug("=VMS_STRUCT= %lx %x\n", *((uint64_t *)curr_elem), size);
                    // hexDump((void*)field->name, curr_elem, size);
#endif
                    /* FIXME */
                    ret = fdl_vmstate_load_state(self, f, field->vmsd, curr_elem,
                                                 field->vmsd->version_id,
                                                 tmp_opaque_ptr);
#ifdef VERBOSE_DEBUG
                    // hexDump((void*)field->name, curr_elem, size);
#endif

                } else {
                    ret = get_handler(self, f, curr_elem, size, field,
                                      (char *)vmsd->name);
                }
                if (ret >= 0) {
                    ret = qemu_file_get_error(f);
                }
                if (ret < 0) {
                    nyx_debug("RETURNING!\n");
                    return ret;
                }
            }
        } else if (field->flags & VMS_MUST_EXIST) {
            nyx_debug("Input validation failed: %s/%s\n", vmsd->name, field->name);
            return -1;
        } else {
            // nyx_debug("Field does not exist...\n");
        }
        field++;
    }

    /* FIXME */
    ret = fdl_vmstate_subsection_load(self, f, vmsd, opaque);

    if (ret != 0) {
        return ret;
    }

    if (vmsd->post_load) {
#ifdef VERBOSE_DEBUG
        nyx_debug("\tPOSTLOAD Function\n");
#endif
        add_post_fptr(self, vmsd->post_load, version_id, opaque, vmsd->name);
        ret = vmsd->post_load(opaque, version_id);
    }
#ifdef VERBOSE_DEBUG
    nyx_debug("\tTotal Size:%ld\n", total_size);
#endif
    return ret;
}


static int fdl_vmstate_load(state_reallocation_t *self,
                            QEMUFile             *f,
                            SaveStateEntry       *se,
                            int                   version_id)
{
    if (!se->vmsd) { /* Old style */
        return se->ops->load_state(f, se->opaque, version_id);
    }

    uintptr_t *t = (uintptr_t *)&(se->opaque);
    return fdl_vmstate_load_state(self, f, se->vmsd, se->opaque, version_id,
                                  (uintptr_t *)t);
}

static int fdl_enumerate_section(state_reallocation_t   *self,
                                 QEMUFile               *f,
                                 MigrationIncomingState *mis)
{
    uint32_t        instance_id, version_id, section_id;
    SaveStateEntry *se;

    char idstr[256];
    int  ret;

    /* Read section start */
    section_id = qemu_get_be32(f);
    if (!qemu_get_counted_string(f, idstr)) {
        nyx_error("Unable to read ID string for section %u", section_id);
        return -EINVAL;
    }
    instance_id = qemu_get_be32(f);
    version_id  = qemu_get_be32(f);

    /* Find savevm section */
    se = fdl_find_se(idstr, instance_id);
    if (se == NULL) {
        nyx_error("Unknown savevm section or instance '%s' %d", idstr, instance_id);
        return -EINVAL;
    }

    /* Validate version */
    if (version_id > se->version_id) {
        nyx_error("savevm: unsupported version %d for '%s' v%d", version_id, idstr,
                  se->version_id);
        return -EINVAL;
    }

    se->load_version_id = version_id;
    se->load_section_id = section_id;

    if (se->vmsd &&
        ((strcmp("tiMer", (const char *)(VMStateDescription *)(se->vmsd)->name))
         /*
         && (strcmp("cpu_common", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("cpu", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("kvm-tpr-opt", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("apic", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("kvmclock", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("fw_cfg", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("PCIBUS", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("I440FX", (VMStateDescription *)(se->vmsd)->name))

         && (strcmp("PIIX3", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("i8259", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("ioapic", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("vga", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("hpet", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("mc146818rtc", (VMStateDescription *)(se->vmsd)->name))

         && (strcmp("i8254", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("pcspk", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("dma", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("serial", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("parallel_isa", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("fdc", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("ps2kbd", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("ps2mouse", (VMStateDescription *)(se->vmsd)->name))


         && (strcmp("pckbd", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("vmmouse", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("port92", (VMStateDescription *)(se->vmsd)->name))
         */
         //&& (strcmp("e1000", (VMStateDescription *)(se->vmsd)->name))
         /*
         && (strcmp("ide", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("i2c_bus", (VMStateDescription *)(se->vmsd)->name))

         && (strcmp("piix4_pm", (VMStateDescription *)(se->vmsd)->name))
         && (strcmp("acpi_build", (VMStateDescription *)(se->vmsd)->name))
         */


         ))
    {
        ret = fdl_vmstate_load(self, f, se, version_id);
    } else {
        nyx_debug("---------------------------------\nVMSD2: %p\n", (void *)se->vmsd);
        ret = vmstate_load(f, se);
    }

    if (ret < 0) {
        nyx_error("failed to load state for instance 0x%x of device '%s'",
                  instance_id, idstr);
        return ret;
    }

    qemu_get_byte(f);
    qemu_get_be32(f);

    return 0;
}

static void fdl_enumerate_global_states(state_reallocation_t *self, QEMUFile *f)
{
    ((struct QEMUFile_tmp *)f)->pos       = 0;
    ((struct QEMUFile_tmp *)f)->buf_index = 0;
    ((struct QEMUFile_tmp *)f)->buf_size  = 0;

    uint8_t section_type;

    MigrationIncomingState *mis = migration_incoming_get_current();

    qemu_get_be32(f);
    qemu_get_be32(f);
    qemu_get_byte(f);

    /* migration state */
    vmstate_load_state(f, (VMStateDescription *)&vmstate_configuration,
                       (void *)&savevm_state, 0);

    while ((section_type = qemu_get_byte(f)) != QEMU_VM_EOF) {
        switch (section_type) {
        case QEMU_VM_SECTION_START:
        case QEMU_VM_SECTION_FULL:
            fdl_enumerate_section(self, f, mis);
            break;
        default:
            /* oops */
            nyx_error("==> ERROR: unkown section_type: %x\n", section_type);
            // abort();
            break;
        }
    }
}

state_reallocation_t *state_reallocation_new(QEMUFile *f)
{
    state_reallocation_t *self = malloc(sizeof(state_reallocation_t));
    self->fast_state_pos       = 0;
    self->fast_state_size      = REALLOC_SIZE;
    self->ptr                  = malloc(sizeof(void *) * REALLOC_SIZE);
    self->copy                 = malloc(sizeof(void *) * REALLOC_SIZE);
    self->size                 = malloc(sizeof(size_t) * REALLOC_SIZE);

    self->fast_state_fptr_pos  = 0;
    self->fast_state_fptr_size = REALLOC_SIZE;

    self->fptr    = malloc(sizeof(void *) * REALLOC_SIZE);
    self->opaque  = malloc(sizeof(void *) * REALLOC_SIZE);
    self->version = malloc(sizeof(uint32_t) * REALLOC_SIZE);

    self->fast_state_get_fptr_pos  = 0;
    self->fast_state_get_fptr_size = REALLOC_SIZE;

    self->get_fptr   = malloc(sizeof(void *) * REALLOC_SIZE);
    self->get_opaque = malloc(sizeof(void *) * REALLOC_SIZE);
    self->get_size   = malloc(sizeof(size_t) * REALLOC_SIZE);
    self->get_data   = malloc(sizeof(void *) * REALLOC_SIZE);

    self->pre_alloc_block = (uint32_t *)mmap(NULL, PRE_ALLOC_BLOCK_SIZE,
                                             PROT_READ | PROT_WRITE,
                                             MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    assert(self->pre_alloc_block != (void *)-1);
    self->pre_alloc_block_offset = 0;

    self->tmp_snapshot.enabled         = false;
    self->tmp_snapshot.fast_state_size = 0;

    // actually enumerate the devices here
    fdl_enumerate_global_states(self, f);

    self->tmp_snapshot.copy = malloc(sizeof(void *) * self->fast_state_pos);
    self->tmp_snapshot.fast_state_size = self->fast_state_pos;

    for (uint32_t i = 0; i < self->fast_state_pos; i++) {
        self->tmp_snapshot.copy[i] = malloc(self->size[i]);
    }
    return self;
}

void fdl_fast_reload(state_reallocation_t *self)
{
    for (uint32_t i = 0; i < self->fast_state_fptr_pos; i++) {
        if ((self->version[i]) == 1337) {
            ((int (*)(void *opaque))self->fptr[i])(self->opaque[i]);
        }
    }

    if (!self->tmp_snapshot.enabled) {
        for (uint32_t i = 0; i < self->fast_state_pos; i++) {
            memcpy(self->ptr[i], self->copy[i], self->size[i]);
        }
    } else {
        for (uint32_t i = 0; i < self->fast_state_pos; i++) {
            memcpy(self->ptr[i], self->tmp_snapshot.copy[i], self->size[i]);
        }
    }

    for (uint32_t i = 0; i < self->fast_state_fptr_pos; i++) {
        if ((self->version[i]) != 1337) {
            ((int (*)(void *opaque, int version_id))self->fptr[i])(self->opaque[i],
                                                                   self->version[i]);
        }
    }
}

void fdl_fast_create_tmp(state_reallocation_t *self)
{
    for (uint32_t i = 0; i < self->fast_state_fptr_pos; i++) {
        if ((self->version[i]) == 1337) {
            ((int (*)(void *opaque))self->fptr[i])(self->opaque[i]);
        } else {
            //((int (*)(void *opaque, int version_id))self->fptr[i])(self->opaque[i], self->version[i]);
        }
    }

    for (uint32_t i = 0; i < self->fast_state_pos; i++) {
        memcpy(self->tmp_snapshot.copy[i], self->ptr[i], self->size[i]);
    }


    for (uint32_t i = 0; i < self->fast_state_fptr_pos; i++) {
        if ((self->version[i]) == 1337) {
            //((int (*)(void *opaque))self->fptr[i])(self->opaque[i]);
        } else {
            ((int (*)(void *opaque, int version_id))self->fptr[i])(self->opaque[i],
                                                                   self->version[i]);
        }
    }
}

void fdl_fast_enable_tmp(state_reallocation_t *self)
{
    self->tmp_snapshot.enabled = true;
}

void fdl_fast_disable_tmp(state_reallocation_t *self)
{
    self->tmp_snapshot.enabled = false;
}
