
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
    	debug_fprintf(stderr, "[%s] Could not open file %s.\n", __func__, tmp);
        assert(false);
        //exit(EXIT_FAILURE);                                         
    }

    qemu_nyx_state_t* nyx_global_state = GET_GLOBAL_STATE();

    debug_printf("DUMPING global_state.pt_ip_filter_configured: -\n");
    fwrite(&nyx_global_state->pt_ip_filter_configured, sizeof(bool)*4, 1, fp);

    debug_printf("DUMPING global_state.pt_ip_filter_a: -\n");
    fwrite(&nyx_global_state->pt_ip_filter_a, sizeof(uint64_t)*4, 1, fp);

    debug_printf("DUMPING global_state.pt_ip_filter_b: -\n");
    fwrite(&nyx_global_state->pt_ip_filter_b, sizeof(uint64_t)*4, 1, fp);

    debug_printf("DUMPING global_state.parent_cr3: %lx\n", global_state.parent_cr3);
    fwrite(&nyx_global_state->parent_cr3, sizeof(uint64_t), 1, fp);
    
    debug_printf("DUMPING global_state.disassembler_word_width: %x\n", global_state.disassembler_word_width);
    fwrite(&nyx_global_state->disassembler_word_width, sizeof(uint8_t), 1, fp);
    debug_printf("DUMPING global_state.fast_reload_pre_image: %x\n", global_state.fast_reload_pre_image);
    fwrite(&nyx_global_state->fast_reload_pre_image, sizeof(bool), 1, fp);

    debug_printf("DUMPING global_state.mem_mode: %x\n", global_state.mem_mode);
    fwrite(&nyx_global_state->mem_mode, sizeof(uint8_t), 1, fp);

    debug_printf("DUMPING global_state.pt_trace_mode: %x\n", global_state.pt_trace_mode);
    fwrite(&nyx_global_state->pt_trace_mode, sizeof(bool), 1, fp);

    debug_printf("DUMPING global_state.nested: %x\n", global_state.nested);
    fwrite(&nyx_global_state->nested, sizeof(bool), 1, fp);

    if(!global_state.nested){
        debug_printf("DUMPING global_state.payload_buffer: %lx\n", global_state.payload_buffer);
        fwrite(&nyx_global_state->payload_buffer, sizeof(uint64_t), 1, fp);

        fwrite(&nyx_global_state->cap_timeout_detection, sizeof(global_state.cap_timeout_detection), 1, fp);
        fwrite(&nyx_global_state->cap_only_reload_mode, sizeof(global_state.cap_only_reload_mode), 1, fp);
        fwrite(&nyx_global_state->cap_compile_time_tracing, sizeof(global_state.cap_compile_time_tracing), 1, fp);
        fwrite(&nyx_global_state->cap_ijon_tracing, sizeof(global_state.cap_ijon_tracing), 1, fp);
        fwrite(&nyx_global_state->cap_cr3, sizeof(global_state.cap_cr3), 1, fp);
        fwrite(&nyx_global_state->cap_compile_time_tracing_buffer_vaddr, sizeof(global_state.cap_compile_time_tracing_buffer_vaddr), 1, fp);
        fwrite(&nyx_global_state->cap_ijon_tracing_buffer_vaddr, sizeof(global_state.cap_ijon_tracing_buffer_vaddr), 1, fp);
        fwrite(&nyx_global_state->protect_payload_buffer, sizeof(bool), 1, fp);
    }
    else{
        assert(global_state.nested_payload_pages != NULL && global_state.nested_payload_pages_num != 0);
        debug_printf("DUMPING global_state.nested_payload_pages_num: %x\n", global_state.nested_payload_pages_num);
        fwrite(&nyx_global_state->nested_payload_pages_num, sizeof(uint32_t), 1, fp);

        if(global_state.nested_payload_pages_num != 0){
            debug_printf("DUMPING global_state.protect_payload_buffer: %x\n", global_state.protect_payload_buffer);
            fwrite(&nyx_global_state->protect_payload_buffer, sizeof(bool), 1, fp);
        }

        for(uint32_t i = 0; i < global_state.nested_payload_pages_num; i++){
            debug_printf("DUMPING global_state.nested_payload_pages[%d]: %lx\n", i, global_state.nested_payload_pages[i]);
            fwrite(&nyx_global_state->nested_payload_pages[i], sizeof(uint64_t), 1, fp);
        }
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
    
    qemu_nyx_state_t* nyx_global_state = GET_GLOBAL_STATE();

    assert(fread(&nyx_global_state->pt_ip_filter_configured, sizeof(bool)*4, 1, fp) == 1);
    debug_printf("LOADING global_state.pt_ip_filter_configured: -\n");

    assert(fread(&nyx_global_state->pt_ip_filter_a, sizeof(uint64_t)*4, 1, fp) == 1);
    debug_printf("LOADING global_state.pt_ip_filter_a: -\n");

    assert(fread(&nyx_global_state->pt_ip_filter_b, sizeof(uint64_t)*4, 1, fp) == 1);
    debug_printf("LOADING global_state.pt_ip_filter_b: -\n");

    assert(fread(&nyx_global_state->parent_cr3, sizeof(uint64_t), 1, fp) == 1);
    debug_printf("LOADING global_state.parent_cr3: %lx\n", global_state.parent_cr3);

    assert(fread(&nyx_global_state->disassembler_word_width, sizeof(uint8_t), 1, fp) == 1);
    debug_printf("LOADING global_state.disassembler_word_width: %x\n", global_state.disassembler_word_width);

    assert(fread(&nyx_global_state->fast_reload_pre_image, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.fast_reload_pre_image: %x\n", global_state.fast_reload_pre_image);

    assert(fread(&nyx_global_state->mem_mode, sizeof(uint8_t), 1, fp) == 1);
    debug_printf("LOADING global_state.mem_mode: %x\n", global_state.mem_mode);

    assert(fread(&nyx_global_state->pt_trace_mode, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.pt_trace_mode: %x\n", global_state.pt_trace_mode);

    assert(fread(&nyx_global_state->nested, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.nested: %x\n", global_state.nested);

    if(!global_state.nested){
        assert(fread(&nyx_global_state->payload_buffer, sizeof(uint64_t), 1, fp) == 1);
        debug_printf("LOADING global_state.payload_buffer: %lx\n", global_state.payload_buffer);

        assert(fread(&nyx_global_state->cap_timeout_detection, sizeof(global_state.cap_timeout_detection), 1, fp) == 1);
        assert(fread(&nyx_global_state->cap_only_reload_mode, sizeof(global_state.cap_only_reload_mode), 1, fp) == 1);
        assert(fread(&nyx_global_state->cap_compile_time_tracing, sizeof(global_state.cap_compile_time_tracing), 1, fp) == 1);
        assert(fread(&nyx_global_state->cap_ijon_tracing, sizeof(global_state.cap_ijon_tracing), 1, fp) == 1);
        assert(fread(&nyx_global_state->cap_cr3, sizeof(global_state.cap_cr3), 1, fp) == 1);
        assert(fread(&nyx_global_state->cap_compile_time_tracing_buffer_vaddr, sizeof(global_state.cap_compile_time_tracing_buffer_vaddr), 1, fp) == 1);
        assert(fread(&nyx_global_state->cap_ijon_tracing_buffer_vaddr, sizeof(global_state.cap_ijon_tracing_buffer_vaddr), 1, fp) == 1);

        if(!global_state.fast_reload_pre_image){
            assert(fread(&nyx_global_state->protect_payload_buffer, sizeof(bool), 1, fp) == 1);
            if(global_state.payload_buffer != 0){
                debug_printf("REMAP PAYLOAD BUFFER!\n");
                remap_payload_buffer(global_state.payload_buffer, ((CPUState *)qemu_get_cpu(0)) );
            }
            else{
                fprintf(stderr, "WARNING: address of payload buffer in snapshot file is zero!\n");
            }
        }

        assert(apply_capabilities(qemu_get_cpu(0)));
    }
    else{
        assert(fread(&nyx_global_state->nested_payload_pages_num, sizeof(uint32_t), 1, fp) == 1);
        debug_printf("LOADING global_state.nested_payload_pages_num: %x\n", global_state.nested_payload_pages_num);

        global_state.in_fuzzing_mode = true; /* haaaeeeeh ??? */
        if(!global_state.fast_reload_pre_image){

            assert(fread(&nyx_global_state->protect_payload_buffer, sizeof(bool), 1, fp) == 1);
            debug_printf("LOADING global_state.protect_payload_buffer: %x\n", global_state.protect_payload_buffer);

            global_state.nested_payload_pages = (uint64_t*)malloc(sizeof(uint64_t)*global_state.nested_payload_pages_num);
            
            for(uint32_t i = 0; i < global_state.nested_payload_pages_num; i++){
                assert(fread(&nyx_global_state->nested_payload_pages[i], sizeof(uint64_t), 1, fp) == 1);
                debug_printf("LOADED global_state.nested_payload_pages[%d]: %lx\n", i, global_state.nested_payload_pages[i]);
                if(global_state.protect_payload_buffer){
                    assert(remap_payload_slot_protected(GET_GLOBAL_STATE()->nested_payload_pages[i], i, ((CPUState *)qemu_get_cpu(0))) == true);
		        }
                else{
                    remap_payload_slot(global_state.nested_payload_pages[i], i, ((CPUState *)qemu_get_cpu(0)));
                }
            }
            
        }
    }
   
    fclose(fp);

	free(tmp);
}