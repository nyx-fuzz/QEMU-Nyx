
#include "qemu/osdep.h"
#include "sysemu/cpus.h"
#include "nyx/state/snapshot_state.h"
#include "nyx/debug.h"
#include "nyx/memory_access.h"
#include "nyx/state/state.h"
#include <stdint.h>
#include <stdio.h>

void serialize_state(const char *filename_prefix, bool is_pre_snapshot)
{
    nyx_trace();

    char *tmp;

    assert(asprintf(&tmp, "%s/global.state", filename_prefix) != -1);

    FILE *fp = fopen(tmp, "wb");
    if (fp == NULL) {
        nyx_error("[%s] Could not open file %s.\n", __func__, tmp);
        assert(false);
    }

    serialized_state_header_t header = { 0 };

    header.magic   = NYX_SERIALIZED_STATE_MAGIC;
    header.version = NYX_SERIALIZED_STATE_VERSION;

    if (is_pre_snapshot) {
        header.type = NYX_SERIALIZED_TYPE_PRE_SNAPSHOT;
        fwrite(&header, sizeof(serialized_state_header_t), 1, fp);
    } else {
        header.type = NYX_SERIALIZED_TYPE_ROOT_SNAPSHOT;
        fwrite(&header, sizeof(serialized_state_header_t), 1, fp);

        qemu_nyx_state_t                *nyx_global_state = GET_GLOBAL_STATE();
        serialized_state_root_snapshot_t root_snapshot    = { 0 };

        for (uint8_t i = 0; i < 4; i++) {
            root_snapshot.pt_ip_filter_configured[i] =
                nyx_global_state->pt_ip_filter_configured[i];
            root_snapshot.pt_ip_filter_a[i] = nyx_global_state->pt_ip_filter_a[i];
            root_snapshot.pt_ip_filter_b[i] = nyx_global_state->pt_ip_filter_b[i];
        }
        root_snapshot.parent_cr3 = nyx_global_state->parent_cr3;
        root_snapshot.disassembler_word_width =
            nyx_global_state->disassembler_word_width;
        root_snapshot.fast_reload_pre_image = nyx_global_state->fast_reload_pre_image;
        root_snapshot.mem_mode      = nyx_global_state->mem_mode;
        root_snapshot.pt_trace_mode = nyx_global_state->pt_trace_mode;

        root_snapshot.input_buffer_vaddr = nyx_global_state->payload_buffer;
        root_snapshot.protect_input_buffer = nyx_global_state->protect_payload_buffer;

        root_snapshot.input_buffer_size = nyx_global_state->input_buffer_size;

        root_snapshot.cap_timeout_detection = nyx_global_state->cap_timeout_detection;
        root_snapshot.cap_only_reload_mode = nyx_global_state->cap_only_reload_mode;
        root_snapshot.cap_compile_time_tracing =
            nyx_global_state->cap_compile_time_tracing;
        root_snapshot.cap_ijon_tracing = nyx_global_state->cap_ijon_tracing;
        root_snapshot.cap_cr3          = nyx_global_state->cap_cr3;
        root_snapshot.cap_compile_time_tracing_buffer_vaddr =
            nyx_global_state->cap_compile_time_tracing_buffer_vaddr;
        root_snapshot.cap_ijon_tracing_buffer_vaddr =
            nyx_global_state->cap_ijon_tracing_buffer_vaddr;
        root_snapshot.cap_coverage_bitmap_size =
            nyx_global_state->cap_coverage_bitmap_size;

        fwrite(&root_snapshot, sizeof(serialized_state_root_snapshot_t), 1, fp);
    }

    fclose(fp);
    free(tmp);
}

void deserialize_state(const char *filename_prefix)
{
    nyx_trace();

    char *tmp;

    assert(asprintf(&tmp, "%s/global.state", filename_prefix) != -1);

    FILE *fp = fopen(tmp, "rb");
    if (fp == NULL) {
        nyx_debug("[%s] Could not open file %s.\n", __func__, tmp);
        assert(false);
    }


    serialized_state_header_t header = { 0 };
    assert(fread(&header, sizeof(serialized_state_header_t), 1, fp) == 1);

    assert(header.magic == NYX_SERIALIZED_STATE_MAGIC);
    assert(header.version == NYX_SERIALIZED_STATE_VERSION);

    if (header.type == NYX_SERIALIZED_TYPE_PRE_SNAPSHOT) {
        /* we're done here */
    } else if (header.type == NYX_SERIALIZED_TYPE_ROOT_SNAPSHOT) {
        qemu_nyx_state_t                *nyx_global_state = GET_GLOBAL_STATE();
        serialized_state_root_snapshot_t root_snapshot    = { 0 };
        assert(fread(&root_snapshot, sizeof(serialized_state_root_snapshot_t), 1,
                     fp) == 1);

        for (uint8_t i = 0; i < 4; i++) {
            nyx_global_state->pt_ip_filter_configured[i] =
                root_snapshot.pt_ip_filter_configured[i];
            nyx_global_state->pt_ip_filter_a[i] = root_snapshot.pt_ip_filter_a[i];
            nyx_global_state->pt_ip_filter_b[i] = root_snapshot.pt_ip_filter_b[i];
        }

        nyx_global_state->parent_cr3 = root_snapshot.parent_cr3;
        nyx_global_state->disassembler_word_width =
            root_snapshot.disassembler_word_width;
        nyx_global_state->fast_reload_pre_image = root_snapshot.fast_reload_pre_image;
        nyx_global_state->mem_mode      = root_snapshot.mem_mode;
        nyx_global_state->pt_trace_mode = root_snapshot.pt_trace_mode;

        nyx_global_state->payload_buffer = root_snapshot.input_buffer_vaddr;
        nyx_global_state->protect_payload_buffer = root_snapshot.protect_input_buffer;

        nyx_global_state->input_buffer_size = root_snapshot.input_buffer_size;

        nyx_global_state->cap_timeout_detection = root_snapshot.cap_timeout_detection;
        nyx_global_state->cap_only_reload_mode = root_snapshot.cap_only_reload_mode;
        nyx_global_state->cap_compile_time_tracing =
            root_snapshot.cap_compile_time_tracing;
        nyx_global_state->cap_ijon_tracing = root_snapshot.cap_ijon_tracing;
        nyx_global_state->cap_cr3          = root_snapshot.cap_cr3;
        nyx_global_state->cap_compile_time_tracing_buffer_vaddr =
            root_snapshot.cap_compile_time_tracing_buffer_vaddr;
        nyx_global_state->cap_ijon_tracing_buffer_vaddr =
            root_snapshot.cap_ijon_tracing_buffer_vaddr;
        nyx_global_state->cap_coverage_bitmap_size =
            root_snapshot.cap_coverage_bitmap_size;

        assert(apply_capabilities(qemu_get_cpu(0)));
        remap_payload_buffer(nyx_global_state->payload_buffer,
                             ((CPUState *)qemu_get_cpu(0)));

        /* makes sure that we are allowed to enter the fuzzing loop */
        nyx_global_state->get_host_config_done  = true;
        nyx_global_state->set_agent_config_done = true;
    } else {
        nyx_error("this feature is currently missing\n");
        abort();
    }

    fclose(fp);

    free(tmp);
}

static bool yaml_write_bool(FILE *fp, const char *key, bool value)
{
    return fprintf(fp, "    %s: %s\n", key, value ? "true" : "false") != -1;
}

static bool yaml_write_uint64_x(FILE *fp, const char *key, uint64_t value)
{
    return fprintf(fp, "    %s: 0x%" PRIx64 "\n", key, value) != -1;
}

static bool yaml_write_uint64_d(FILE *fp, const char *key, uint64_t value)
{
    return fprintf(fp, "    %s: %" PRId64 "\n", key, value) != -1;
}

static bool yaml_write_uint64_x_range(FILE *fp, const char *key, uint64_t value_a, uint64_t value_b)
{
    return fprintf(fp, "    %s: [0x%" PRIx64 ", 0x%" PRIx64 "]\n", key, value_a, value_b) != -1;
}

static void yaml_write_mem_mode(FILE *fp, const char *key, mem_mode_t value)
{
    switch (value) {
        case mm_unkown:
            assert(fprintf(fp, "    %s: \"mm_unkown\"\n", key) != 1);
            break;
        case mm_32_protected:   /* 32 Bit / No MMU */
            assert(fprintf(fp, "    %s: \"mm_32_protected\"\n", key) != 1);
            break;
        case mm_32_paging:      /* 32 Bit / PAE Paging */
            assert(fprintf(fp, "    %s: \"mm_32_paging\"\n", key) != 1);
            break;
        case mm_32_pae:         /* 32 Bit / PAE Paging */
            assert(fprintf(fp, "    %s: \"mm_32_pae\"\n", key) != 1);
            break;
        case mm_64_l4_paging:   /* 64 Bit / L4 Paging */
            assert(fprintf(fp, "    %s: \"mm_64_l4_paging\"\n", key) != 1);
            break;
        case mm_64_l5_paging:   /* 64 Bit / L5 Paging */
            assert(fprintf(fp, "    %s: \"mm_64_l5_paging\"\n", key) != 1);
            break;
    }
}

/* Helper function to serialize the meta data of a snapshot to yaml.
 * This function is only called in case a root snapshot is created.
 * The data written to the yaml file is not used later on, but can be used
 * by the frontend to get specific information about the snapshot.
 */
void serialize_root_snapshot_meta_data(const char *snapshot_dir){
    nyx_trace();

    char *tmp;

    assert(asprintf(&tmp, "%s/state.yaml", snapshot_dir) != -1);

    FILE *fp = fopen(tmp, "wb");
    if (fp == NULL) {
        nyx_error("[%s] Could not open file %s.\n", __func__, tmp);
        assert(false);
    }

    qemu_nyx_state_t *nyx_global_state = GET_GLOBAL_STATE();

    assert(fprintf(fp, "---\n") != -1);

    assert(fprintf(fp, "qemu_nyx:\n") != 1);
    assert(yaml_write_uint64_x(fp, "nyx_serialized_state_version", NYX_SERIALIZED_STATE_VERSION));
    assert(fprintf(fp, "\n") != -1);

    assert(fprintf(fp, "processor_trace:\n") != 1);
    for (uint8_t i = 0; i < 4; i++) {
        char* key = NULL;
        assert(asprintf(&key, "pt_ip_filter_configured_%d", i) != -1);
        assert(yaml_write_bool(fp, key, nyx_global_state->pt_ip_filter_configured[i]));
        free(key);
    }

    for (uint8_t i = 0; i < 4; i++) {
        char* key = NULL;
        assert(asprintf(&key, "pt_ip_filter_%d", i) != -1);
        assert(yaml_write_uint64_x_range(fp, key, nyx_global_state->pt_ip_filter_a[i], nyx_global_state->pt_ip_filter_b[i]));
        free(key);
    }

    assert(yaml_write_uint64_x(fp, "parent_cr3", nyx_global_state->parent_cr3));
    /* TODO: remove disassembler_word_width (it is actually not used or set anymore) */
    //assert(yaml_write_uint64_d(fp, "disassembler_word_width", nyx_global_state->disassembler_word_width));
    //assert(yaml_write_uint64_x(fp, "fast_reload_pre_image", nyx_global_state->fast_reload_pre_image));
    yaml_write_mem_mode(fp, "mem_mode", nyx_global_state->mem_mode);
    assert(yaml_write_bool(fp, "pt_trace_mode", nyx_global_state->pt_trace_mode));
    assert(fprintf(fp, "\n") != -1);


    assert(fprintf(fp, "input_buffer:\n") != -1);
    assert(yaml_write_uint64_x(fp, "input_buffer_vaddr", nyx_global_state->payload_buffer));
    assert(yaml_write_bool(fp, "protect_input_buffer", nyx_global_state->protect_payload_buffer));
    assert(yaml_write_uint64_x(fp, "input_buffer_size", nyx_global_state->input_buffer_size));
    assert(fprintf(fp, "\n") != -1);


    assert(fprintf(fp, "capabilites:\n") != -1);
    assert(yaml_write_bool(fp, "cap_timeout_detection", nyx_global_state->cap_timeout_detection));
    assert(yaml_write_bool(fp, "cap_only_reload_mode", nyx_global_state->cap_only_reload_mode));
    assert(yaml_write_bool(fp, "cap_compile_time_tracing", nyx_global_state->cap_compile_time_tracing));
    assert(yaml_write_bool(fp, "cap_ijon_tracing", nyx_global_state->cap_ijon_tracing));
    assert(yaml_write_bool(fp, "cap_cr3", nyx_global_state->cap_cr3));
    assert(yaml_write_uint64_x(fp, "cap_compile_time_tracing_buffer_vaddr", nyx_global_state->cap_compile_time_tracing_buffer_vaddr));
    assert(yaml_write_uint64_x(fp, "cap_ijon_tracing_buffer_vaddr", nyx_global_state->cap_ijon_tracing_buffer_vaddr));
    assert(yaml_write_uint64_x(fp, "cap_coverage_bitmap_size", nyx_global_state->cap_coverage_bitmap_size));
    assert(fprintf(fp, "\n") != -1);

    assert(fprintf(fp, "...\n") != -1);
    fclose(fp);
    free(tmp);
}