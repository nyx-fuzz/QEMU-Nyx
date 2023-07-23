#pragma once

#include <stdbool.h>
#include <stdint.h>

#define NYX_SERIALIZED_STATE_MAGIC   0x58594E
#define NYX_SERIALIZED_STATE_VERSION 1

#define NYX_SERIALIZED_TYPE_PRE_SNAPSHOT    0
#define NYX_SERIALIZED_TYPE_ROOT_SNAPSHOT   1
#define NYX_SERIALIZED_TYPE_NESTED_SNAPSHOT 2

typedef struct serialized_state_header_s {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
} serialized_state_header_t;

typedef struct serialized_state_root_snapshot_s {
    bool     pt_ip_filter_configured[4];
    uint64_t pt_ip_filter_a[4];
    uint64_t pt_ip_filter_b[4];
    uint64_t parent_cr3;
    uint8_t  disassembler_word_width;
    bool     fast_reload_pre_image;
    uint8_t  mem_mode;
    bool     pt_trace_mode;

    uint64_t input_buffer_vaddr;
    bool     protect_input_buffer;
    uint32_t input_buffer_size;

    uint8_t  cap_timeout_detection;
    uint8_t  cap_only_reload_mode;
    uint8_t  cap_compile_time_tracing;
    uint8_t  cap_ijon_tracing;
    uint64_t cap_cr3;
    uint64_t cap_compile_time_tracing_buffer_vaddr;
    uint64_t cap_ijon_tracing_buffer_vaddr;
    uint64_t cap_coverage_bitmap_size;

} serialized_state_root_snapshot_t;


void serialize_state(const char *filename_prefix, bool is_pre_snapshot);
void deserialize_state(const char *filename_prefix);

void serialize_root_snapshot_meta_data(const char *snapshot_dir);