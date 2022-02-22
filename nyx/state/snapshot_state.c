
#include "qemu/osdep.h"
#include "sysemu/cpus.h"
#include "nyx/state/snapshot_state.h"
#include "nyx/debug.h"
#include "nyx/state/state.h"
#include "nyx/memory_access.h"
#include <stdio.h>

void serialize_state(const char* filename_prefix, bool is_pre_snapshot){
	debug_printf("%s\n", __func__);

	char* tmp;

	assert(asprintf(&tmp, "%s/global.state", filename_prefix) != -1);
	debug_printf("%s\n", tmp);

	FILE *fp = fopen(tmp, "wb");
	if(fp == NULL) {                                                
    	fprintf(stderr, "[%s] Could not open file %s.\n", __func__, tmp);
        assert(false);
    }

    serialized_state_header_t header = {0};

    header.magic = NYX_SERIALIZED_STATE_MAGIC;
    header.version = NYX_SERIALIZED_STATE_VERSION;

    if (is_pre_snapshot){
        header.type = NYX_SERIALIZED_TYPE_PRE_SNAPSHOT;
        fwrite(&header, sizeof(serialized_state_header_t), 1, fp);
    }
    else{
        header.type = NYX_SERIALIZED_TYPE_ROOT_SNAPSHOT;
        fwrite(&header, sizeof(serialized_state_header_t), 1, fp);

        qemu_nyx_state_t* nyx_global_state = GET_GLOBAL_STATE();
        serialized_state_root_snapshot_t root_snapshot = {0};

        for (uint8_t i = 0; i < 4; i++){
            root_snapshot.pt_ip_filter_configured[i] = nyx_global_state->pt_ip_filter_configured[i];
            root_snapshot.pt_ip_filter_a[i] = nyx_global_state->pt_ip_filter_a[i];
            root_snapshot.pt_ip_filter_b[i] = nyx_global_state->pt_ip_filter_b[i];
        }
        root_snapshot.parent_cr3 = nyx_global_state->parent_cr3;
        root_snapshot.disassembler_word_width = nyx_global_state->disassembler_word_width;
        root_snapshot.fast_reload_pre_image = nyx_global_state->fast_reload_pre_image;
        root_snapshot.mem_mode = nyx_global_state->mem_mode;
        root_snapshot.pt_trace_mode =nyx_global_state->pt_trace_mode;

        root_snapshot.input_buffer_vaddr = nyx_global_state->payload_buffer;
        root_snapshot.protect_input_buffer = nyx_global_state->protect_payload_buffer;
        
        root_snapshot.input_buffer_size = nyx_global_state->input_buffer_size;

        root_snapshot.cap_timeout_detection = nyx_global_state->cap_timeout_detection;
        root_snapshot.cap_only_reload_mode = nyx_global_state->cap_only_reload_mode;
        root_snapshot.cap_compile_time_tracing = nyx_global_state->cap_compile_time_tracing;
        root_snapshot.cap_ijon_tracing = nyx_global_state->cap_ijon_tracing;
        root_snapshot.cap_cr3 = nyx_global_state->cap_cr3;
        root_snapshot.cap_compile_time_tracing_buffer_vaddr = nyx_global_state->cap_compile_time_tracing_buffer_vaddr;
        root_snapshot.cap_ijon_tracing_buffer_vaddr = nyx_global_state->cap_ijon_tracing_buffer_vaddr;
        root_snapshot.cap_coverage_bitmap_size = nyx_global_state->cap_coverage_bitmap_size;

        fwrite(&root_snapshot, sizeof(serialized_state_root_snapshot_t), 1, fp);

    }
        
    fclose(fp);
	free(tmp);
}

void deserialize_state(const char* filename_prefix){
	debug_printf("%s\n", __func__);

	char* tmp;

	assert(asprintf(&tmp, "%s/global.state", filename_prefix) != -1);
	debug_printf("%s\n", tmp);

	FILE *fp = fopen(tmp, "rb");
	if(fp == NULL) {                                                
    	debug_fprintf(stderr, "[%s] Could not open file %s.\n", __func__, tmp);
        assert(false);
        //exit(EXIT_FAILURE);                                         
    }


    serialized_state_header_t header = {0};
    assert(fread(&header, sizeof(serialized_state_header_t), 1, fp) == 1);

    assert(header.magic == NYX_SERIALIZED_STATE_MAGIC);
    assert(header.version == NYX_SERIALIZED_STATE_VERSION);

    if(header.type == NYX_SERIALIZED_TYPE_PRE_SNAPSHOT){
        /* we're done here */
    }
    else if (header.type == NYX_SERIALIZED_TYPE_ROOT_SNAPSHOT){
        qemu_nyx_state_t* nyx_global_state = GET_GLOBAL_STATE();
        serialized_state_root_snapshot_t root_snapshot = {0};
        assert(fread(&root_snapshot, sizeof(serialized_state_root_snapshot_t), 1, fp) == 1);

        for (uint8_t i = 0; i < 4; i++){
            nyx_global_state->pt_ip_filter_configured[i] = root_snapshot.pt_ip_filter_configured[i];
            nyx_global_state->pt_ip_filter_a[i] = root_snapshot.pt_ip_filter_a[i];
            nyx_global_state->pt_ip_filter_b[i] = root_snapshot.pt_ip_filter_b[i];
        }

        nyx_global_state->parent_cr3 = root_snapshot.parent_cr3;
        nyx_global_state->disassembler_word_width = root_snapshot.disassembler_word_width;
        nyx_global_state->fast_reload_pre_image = root_snapshot.fast_reload_pre_image;
        nyx_global_state->mem_mode = root_snapshot.mem_mode;
        nyx_global_state->pt_trace_mode =root_snapshot.pt_trace_mode;

        nyx_global_state->payload_buffer = root_snapshot.input_buffer_vaddr;
        nyx_global_state->protect_payload_buffer = root_snapshot.protect_input_buffer;
        
        nyx_global_state->input_buffer_size = root_snapshot.input_buffer_size;

        nyx_global_state->cap_timeout_detection = root_snapshot.cap_timeout_detection;
        nyx_global_state->cap_only_reload_mode = root_snapshot.cap_only_reload_mode;
        nyx_global_state->cap_compile_time_tracing = root_snapshot.cap_compile_time_tracing;
        nyx_global_state->cap_ijon_tracing = root_snapshot.cap_ijon_tracing;
        nyx_global_state->cap_cr3 = root_snapshot.cap_cr3;
        nyx_global_state->cap_compile_time_tracing_buffer_vaddr = root_snapshot.cap_compile_time_tracing_buffer_vaddr;
        nyx_global_state->cap_ijon_tracing_buffer_vaddr = root_snapshot.cap_ijon_tracing_buffer_vaddr;
        nyx_global_state->cap_coverage_bitmap_size = root_snapshot.cap_coverage_bitmap_size;

        assert(apply_capabilities(qemu_get_cpu(0)));
        remap_payload_buffer(nyx_global_state->payload_buffer, ((CPUState *)qemu_get_cpu(0)) );

        /* makes sure that we are allowed to enter the fuzzing loop */
        nyx_global_state->get_host_config_done = true;
        nyx_global_state->set_agent_config_done = true;
    }
    else{
        fprintf(stderr, "[QEMU-Nyx]: this feature is currently missing\n");
        abort();
    }

    fclose(fp);

	free(tmp);
}