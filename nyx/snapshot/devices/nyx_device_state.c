#include "qemu/osdep.h"

#include <immintrin.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "qemu/main-loop.h"
#include "qemu/rcu_queue.h"

#include "block/qapi.h"
#include "exec/ram_addr.h"
#include "migration/global_state.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "migration/qjson.h"
#include "migration/register.h"
#include "migration/savevm.h"
#include "migration/vmstate.h"
#include "sysemu/block-backend.h"
#include "sysemu/cpus.h"
#include "sysemu/kvm.h"
#include "sysemu/reset.h"
#include "sysemu/runstate.h"
#include "sysemu/sysemu.h"

#include "nyx/debug.h"
#include "nyx/snapshot/devices/nyx_device_state.h"
#include "nyx/snapshot/devices/state_reallocation.h"
#include "nyx/snapshot/devices/vm_change_state_handlers.h"

#define STATE_BUFFER 0x8000000 /* up to 128MB */

extern void enable_fast_snapshot_rtc(void);
extern void enable_fast_snapshot_kvm_clock(void);

static void enable_fast_snapshot_mode(void)
{
    enable_fast_snapshot_rtc();
    enable_fast_snapshot_kvm_clock();
}

extern int kvm_nyx_put_tsc_value(CPUState *cs, uint64_t data);

static void set_tsc_value(nyx_device_state_t *self, bool tmp_snapshot)
{
    if (self->incremental_mode) {
        assert(self->tsc_value_incremental);
        assert(kvm_nyx_put_tsc_value(qemu_get_cpu(0), self->tsc_value_incremental) ==
               0);
    } else {
        assert(self->tsc_value);
        assert(kvm_nyx_put_tsc_value(qemu_get_cpu(0), self->tsc_value) == 0);
    }
}

static void save_tsc_value(nyx_device_state_t *self, bool incremental_mode)
{
    X86CPU      *cpu = X86_CPU(qemu_get_cpu(0));
    CPUX86State *env = &cpu->env;

    if (incremental_mode) {
        self->tsc_value_incremental = env->tsc;
    } else {
        self->tsc_value = env->tsc;
    }
}

extern int qemu_savevm_state(QEMUFile *f, Error **errp);

/* new savevm routine */
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
    void                     *opaque;
    void                     *compat;
    int                       is_ram;
} SaveStateEntry;


typedef struct SaveState {
    QTAILQ_HEAD(, SaveStateEntry) handlers;
    int         global_section_id;
    bool        skip_configuration;
    uint32_t    len;
    const char *name;
    uint32_t    target_page_bits;
} SaveState;

extern SaveState savevm_state;

extern void vmstate_save(QEMUFile *f, SaveStateEntry *se, QJSON *vmdesc);
extern bool should_send_vmdesc(void);

extern bool skip_section_footers;


extern void save_section_footer(QEMUFile *f, SaveStateEntry *se);
extern void save_section_header(QEMUFile *f, SaveStateEntry *se, uint8_t section_type);

/* skip block ram */
static void fast_qemu_savevm_state_complete_precopy(QEMUFile *f, bool iterable_only)
{
    QJSON          *vmdesc;
    int             vmdesc_len;
    SaveStateEntry *se;
    int             ret;
    bool            in_postcopy = migration_in_postcopy();

    cpu_synchronize_all_states();

    QTAILQ_FOREACH (se, &savevm_state.handlers, entry) {
        if (strcmp(se->idstr, "ram") && strcmp(se->idstr, "block")) {
            if (!se->ops || (in_postcopy && se->ops->save_live_complete_postcopy) ||
                (in_postcopy && !iterable_only) ||
                !se->ops->save_live_complete_precopy)
            {
                continue;
            }

            if (se->ops && se->ops->is_active) {
                if (!se->ops->is_active(se->opaque)) {
                    continue;
                }
            }

            save_section_header(f, se, QEMU_VM_SECTION_END);

            ret = se->ops->save_live_complete_precopy(f, se->opaque);
            save_section_footer(f, se);
            if (ret < 0) {
                qemu_file_set_error(f, ret);
                return;
            }
        }
    }

    if (iterable_only) {
        return;
    }

    vmdesc = qjson_new();
    json_prop_int(vmdesc, "page_size", TARGET_PAGE_SIZE);
    json_start_array(vmdesc, "devices");
    QTAILQ_FOREACH (se, &savevm_state.handlers, entry) {
        if (strcmp(se->idstr, "ram") && strcmp(se->idstr, "block")) {
            if ((!se->ops || !se->ops->save_state) && !se->vmsd) {
                continue;
            }
            if (se->vmsd && !vmstate_save_needed(se->vmsd, se->opaque)) {
                continue;
            }

            json_start_object(vmdesc, NULL);
            json_prop_str(vmdesc, "name", se->idstr);
            json_prop_int(vmdesc, "instance_id", se->instance_id);

            save_section_header(f, se, QEMU_VM_SECTION_FULL);
            vmstate_save(f, se, vmdesc);
            save_section_footer(f, se);

            json_end_object(vmdesc);
        }
    }

    if (!in_postcopy) {
        /* Postcopy stream will still be going */
        qemu_put_byte(f, QEMU_VM_EOF);
    }

    json_end_array(vmdesc);
    qjson_finish(vmdesc);
    vmdesc_len = strlen(qjson_get_str(vmdesc));

    if (should_send_vmdesc()) {
        qemu_put_byte(f, QEMU_VM_VMDESCRIPTION);
        qemu_put_be32(f, vmdesc_len);
        qemu_put_buffer(f, (uint8_t *)qjson_get_str(vmdesc), vmdesc_len);
    }
    qjson_destroy(vmdesc);

    qemu_fflush(f);
}


static int fast_qemu_savevm_state_iterate(QEMUFile *f, bool postcopy)
{
    SaveStateEntry *se;
    int             ret = 1;

    QTAILQ_FOREACH (se, &savevm_state.handlers, entry) {
        if (strcmp(se->idstr, "ram") && strcmp(se->idstr, "block")) {
            if (!se->ops || !se->ops->save_live_iterate) {
                continue;
            }
            if (se->ops && se->ops->is_active) {
                if (!se->ops->is_active(se->opaque)) {
                    continue;
                }
            }
            /*
             * In the postcopy phase, any device that doesn't know how to
             * do postcopy should have saved it's state in the _complete
             * call that's already run, it might get confused if we call
             * iterate afterwards.
             */
            if (postcopy && !se->ops->save_live_complete_postcopy) {
                continue;
            }
            if (qemu_file_rate_limit(f)) {
                return 0;
            }

            save_section_header(f, se, QEMU_VM_SECTION_PART);

            ret = se->ops->save_live_iterate(f, se->opaque);
            save_section_footer(f, se);

            if (ret < 0) {
                qemu_file_set_error(f, ret);
            }
            if (ret <= 0) {
                /* Do not proceed to the next vmstate before this one reported
                   completion of the current stage. This serializes the migration
                   and reduces the probability that a faster changing state is
                   synchronized over and over again. */
                break;
            }
        }
    }
    return ret;
}

static void fast_qemu_savevm_state_setup(QEMUFile *f)
{
    SaveStateEntry *se;
    int             ret;

    QTAILQ_FOREACH (se, &savevm_state.handlers, entry) {
        if (strcmp(se->idstr, "ram") && strcmp(se->idstr, "block")) {
            if (!se->ops || !se->ops->save_setup) {
                continue;
            }
            if (se->ops && se->ops->is_active) {
                if (!se->ops->is_active(se->opaque)) {
                    continue;
                }
            }
            save_section_header(f, se, QEMU_VM_SECTION_START);

            ret = se->ops->save_setup(f, se->opaque);
            save_section_footer(f, se);
            if (ret < 0) {
                qemu_file_set_error(f, ret);
                break;
            }
        }
    }
}


static int fast_qemu_savevm_state(QEMUFile *f, Error **errp)
{
    qemu_savevm_state_header(f);
    fast_qemu_savevm_state_setup(f);

    while (qemu_file_get_error(f) == 0) {
        if (fast_qemu_savevm_state_iterate(f, false) > 0) {
            fast_qemu_savevm_state_complete_precopy(f, false);
            break;
        }
    }

    return 0;
}

/* QEMUFile RAM Emulation */
static ssize_t fast_savevm_writev_buffer(void         *opaque,
                                         struct iovec *iov,
                                         int           iovcnt,
                                         int64_t       pos)
{
    ssize_t retval = 0;
    for (uint32_t i = 0; i < iovcnt; i++) {
        memcpy((void *)(((struct fast_savevm_opaque_t *)(opaque))->buf +
                        ((struct fast_savevm_opaque_t *)(opaque))->pos),
               iov[i].iov_base, iov[i].iov_len);
        ((struct fast_savevm_opaque_t *)(opaque))->pos += iov[i].iov_len;
        retval += iov[i].iov_len;
    }
    return retval;
}


static int fast_savevm_fclose_save_to_buffer(void *opaque)
{
    memcpy(((struct fast_savevm_opaque_t *)(opaque))->output_buffer,
           ((struct fast_savevm_opaque_t *)(opaque))->buf,
           ((struct fast_savevm_opaque_t *)(opaque))->pos);
    *((struct fast_savevm_opaque_t *)(opaque))->output_buffer_size =
        ((struct fast_savevm_opaque_t *)(opaque))->pos;
    // printf("DUMPED: %d\n", *((struct fast_savevm_opaque_t*)(opaque))->output_buffer_size);
    return 0;
}

static int fast_loadvm_fclose(void *opaque)
{
    return 0;
}

static ssize_t fast_loadvm_get_buffer(void *opaque, uint8_t *buf, int64_t pos, size_t size)
{
    memcpy(buf, (void *)(((struct fast_savevm_opaque_t *)(opaque))->buf + pos), size);
    return size;
}

static const QEMUFileOps fast_loadvm_ops = {
    .get_buffer = (QEMUFileGetBufferFunc *)fast_loadvm_get_buffer,
    .close      = (QEMUFileCloseFunc *)fast_loadvm_fclose
};

static const QEMUFileOps fast_savevm_ops_to_buffer = {
    .writev_buffer = (QEMUFileWritevBufferFunc *)fast_savevm_writev_buffer,
    .close         = (QEMUFileCloseFunc *)fast_savevm_fclose_save_to_buffer
};


nyx_device_state_t *nyx_device_state_init_from_snapshot(const char *snapshot_folder,
                                                        bool        pre_snapshot)
{
    nyx_device_state_t *self = malloc(sizeof(nyx_device_state_t));
    memset(self, 0, sizeof(nyx_device_state_t));

    self->state_buf      = malloc(STATE_BUFFER);
    self->state_buf_size = 0;

    char *qemu_state_file;
    assert(asprintf(&qemu_state_file, "%s/fast_snapshot.qemu_state",
                    snapshot_folder) != -1);

    struct fast_savevm_opaque_t fast_savevm_opaque;
    FILE                       *f;

    uint8_t ret = global_state_store();
    assert(!ret);

    struct stat buffer;
    assert(stat(qemu_state_file, &buffer) == 0);

    void *state_buf2 = malloc(STATE_BUFFER);

    f = fopen(qemu_state_file, "r");
    assert(fread(state_buf2, buffer.st_size, 1, f) == 1);
    fclose(f);

    fast_savevm_opaque.buf = state_buf2;
    fast_savevm_opaque.f   = NULL;
    fast_savevm_opaque.pos = 0;
    QEMUFile *file_dump    = qemu_fopen_ops(&fast_savevm_opaque, &fast_loadvm_ops);

    qemu_devices_reset();
    qemu_loadvm_state(file_dump);

    if (!pre_snapshot) {
        self->qemu_state = state_reallocation_new(file_dump);
    }

    free(state_buf2);

    if (!pre_snapshot) {
        enable_fast_snapshot_mode();
        save_tsc_value(self, false);
    }

    return self;
}

/*
 * This is where QemuFile is created for later fast_snapshot creation
 * we use fast_qemu_savevm_state() to create a regular snapshot to QEMUFile
 * backed by RAM. state_reallocation_new() then uses this file to build an
 * optimized sequence of snapshot restore operations.
 */
nyx_device_state_t *nyx_device_state_init(void)
{
    nyx_device_state_t *self = malloc(sizeof(nyx_device_state_t));
    memset(self, 0, sizeof(nyx_device_state_t));

    self->state_buf      = malloc(STATE_BUFFER);
    self->state_buf_size = 0;

    Error                      *local_err = NULL;
    struct fast_savevm_opaque_t fast_savevm_opaque, fast_loadvm_opaque;

    void *tmp_buf = malloc(1024 * 1024 * 16);

    fast_savevm_opaque.output_buffer      = self->state_buf;
    fast_savevm_opaque.output_buffer_size = &self->state_buf_size;

    fast_savevm_opaque.buf = tmp_buf;
    fast_savevm_opaque.f   = NULL;
    fast_savevm_opaque.pos = 0;

    uint8_t ret = global_state_store();
    assert(!ret);

    QEMUFile *f = qemu_fopen_ops(&fast_savevm_opaque, &fast_savevm_ops_to_buffer);
    ret         = fast_qemu_savevm_state(f, &local_err);

    fast_loadvm_opaque.buf = tmp_buf;
    fast_loadvm_opaque.f   = NULL;
    fast_loadvm_opaque.pos = 0;
    QEMUFile *file_dump    = qemu_fopen_ops(&fast_loadvm_opaque, &fast_loadvm_ops);

    self->qemu_state = state_reallocation_new(file_dump);
    qemu_fclose(file_dump);

    qemu_fclose(f);
    free(tmp_buf);

    enable_fast_snapshot_mode();
    save_tsc_value(self, false);
    return self;
}

void nyx_device_state_switch_incremental(nyx_device_state_t *self)
{
    self->incremental_mode = true;
    fdl_fast_create_tmp(self->qemu_state);
    fdl_fast_enable_tmp(self->qemu_state);
}

void nyx_device_state_disable_incremental(nyx_device_state_t *self)
{
    fdl_fast_disable_tmp(self->qemu_state);
    self->incremental_mode = false;
}

void nyx_device_state_restore(nyx_device_state_t *self)
{
    fdl_fast_reload(self->qemu_state);
    call_fast_change_handlers();
}

void nyx_device_state_post_restore(nyx_device_state_t *self)
{
    set_tsc_value(self, self->incremental_mode);
}


void nyx_device_state_save_tsc(nyx_device_state_t *self)
{
    save_tsc_value(self, false);
}


void nyx_device_state_save_tsc_incremental(nyx_device_state_t *self)
{
    save_tsc_value(self, true);
}

void nyx_device_state_serialize(nyx_device_state_t *self, const char *snapshot_folder)
{
    char *tmp;
    assert(asprintf(&tmp, "%s/fast_snapshot.qemu_state", snapshot_folder) != -1);

    FILE *f_qemu_state = fopen(tmp, "w+b");
    assert(fwrite(self->state_buf, 1, self->state_buf_size, f_qemu_state) ==
           self->state_buf_size);
    fclose(f_qemu_state);
}
