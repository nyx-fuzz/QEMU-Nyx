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

#include "nyx/state.h"
#include "nyx/debug.h"
#include "nyx/memory_access.h"
#include "sysemu/kvm.h"
#include "nyx/auxiliary_buffer.h"
#include "nyx/sharedir.h"
#include "nyx/fast_vm_reload_sync.h"
#include "nyx/helpers.h"

//#define STATE_VERBOSE

/* global singleton */
struct state_qemu_pt global_state;

void state_init_global(void){
#ifdef STATE_VERBOSE
    fprintf(stderr, "--> %s <--\n", __func__);
#endif
    /* safety first */
    assert(libxdc_get_release_version() == LIBXDC_RELEASE_VERSION);

    global_state.nyx_fdl = false;

    global_state.workdir_path = NULL;

    global_state.fast_reload_enabled = false;
    global_state.fast_reload_mode = false;
    global_state.fast_reload_path = NULL;
    global_state.fast_reload_pre_path = NULL;
    global_state.fast_reload_pre_image = false;

    global_state.fast_reload_snapshot = fast_reload_new();
    global_state.reload_state = init_fast_vm_reload_sync();

    global_state.decoder = NULL;

    global_state.page_cache = NULL;

    global_state.redqueen_enable_pending = false;
    global_state.redqueen_disable_pending = false;
    global_state.redqueen_instrumentation_mode = 0;
    global_state.redqueen_update_blacklist = false;
    global_state.patches_enable_pending = false;
    global_state.patches_disable_pending = false;
    global_state.redqueen_state = NULL;

    for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
        global_state.pt_ip_filter_configured[i] = false;
		global_state.pt_ip_filter_enabled[i] = false;
		global_state.pt_ip_filter_a[i] = 0x0;
		global_state.pt_ip_filter_b[i] = 0x0;
    }
    global_state.pt_c3_filter = 0;
    
    global_state.enable_hprintf = false;
    global_state.parent_cr3 = 0;
    global_state.disassembler_word_width = 64;
    global_state.nested = false;
    global_state.payload_buffer = 0;
    global_state.nested_payload_pages = NULL;
    global_state.nested_payload_pages_num = 0;
    global_state.protect_payload_buffer = 0; 
    global_state.discard_tmp_snapshot = 0;
    global_state.mem_mode = mm_unkown;

    init_timeout_detector(&(global_state.timeout_detector));

    global_state.in_fuzzing_mode = false;
    global_state.in_reload_mode = true;
    global_state.shutdown_requested = false;
    global_state.cow_cache_full = false;

    global_state.auxilary_buffer = NULL;
    memset(&global_state.shadow_config, 0x0, sizeof(auxilary_buffer_config_t));

    global_state.decoder_page_fault = false;
    global_state.decoder_page_fault_addr = 0x0;

    global_state.dump_page = false;
    global_state.dump_page_addr = 0x0;

    global_state.in_redqueen_reload_mode = false;
    
    global_state.pt_trace_mode = true;
    global_state.pt_trace_mode_force = false;

    global_state.sharedir = sharedir_new();


    global_state.shared_bitmap_fd = 0;
    global_state.shared_bitmap_size = 0;
    global_state.shared_ijon_bitmap_size = 0;
    global_state.shared_payload_buffer_fd = 0;
    global_state.shared_payload_buffer_size = 0;
    global_state.shared_bitmap_ptr = NULL;

    global_state.pt_trace_size = 0;
    global_state.bb_coverage = 0;

    global_state.cap_timeout_detection = 0;
    global_state.cap_only_reload_mode = 0;
    global_state.cap_compile_time_tracing = 0;
    global_state.cap_ijon_tracing = 0;
    global_state.cap_cr3 = 0;
    global_state.cap_compile_time_tracing_buffer_vaddr = 0;
    global_state.cap_ijon_tracing_buffer_vaddr = 0;

    QTAILQ_INIT(&global_state.redqueen_breakpoints);
}


fast_reload_t* get_fast_reload_snapshot(void){
    return global_state.fast_reload_snapshot;
}

void set_fast_reload_mode(bool mode){
    global_state.fast_reload_mode = mode;
}

void set_fast_reload_path(const char* path){
    assert(global_state.fast_reload_path == NULL);
    global_state.fast_reload_path = malloc(strlen(path)+1);
    strcpy(global_state.fast_reload_path, path);
}

void set_fast_reload_pre_path(const char* path){
    assert(global_state.fast_reload_pre_path == NULL);
    global_state.fast_reload_pre_path = malloc(strlen(path)+1);
    strcpy(global_state.fast_reload_pre_path, path);
}

void set_fast_reload_pre_image(void){
    assert(global_state.fast_reload_pre_path != NULL);
    global_state.fast_reload_pre_image = true;
}

void enable_fast_reloads(void){
    assert(global_state.fast_reload_path != NULL);
    global_state.fast_reload_enabled = true;
}

void init_page_cache(char* path){
    assert(global_state.page_cache == NULL);
    global_state.page_cache = page_cache_new((CPUState *)qemu_get_cpu(0), path);
    #ifdef STATE_VERBOSE
    debug_printf("\n\nINIT PAGE_CACHE => %s\n", path);
    #endif
}

page_cache_t* get_page_cache(void){
    assert(global_state.page_cache);
    return global_state.page_cache;
}

void init_redqueen_state(void){
    global_state.redqueen_state = new_rq_state((CPUState *)qemu_get_cpu(0), get_page_cache());
}


redqueen_t* get_redqueen_state(void){
    assert(global_state.redqueen_state != NULL);
    return global_state.redqueen_state;
}


void dump_global_state(const char* filename_prefix){
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


    debug_printf("DUMPING global_state.pt_ip_filter_configured: -\n");
    fwrite(&global_state.pt_ip_filter_configured, sizeof(bool)*4, 1, fp);

    debug_printf("DUMPING global_state.pt_ip_filter_a: -\n");
    fwrite(&global_state.pt_ip_filter_a, sizeof(uint64_t)*4, 1, fp);

    debug_printf("DUMPING global_state.pt_ip_filter_b: -\n");
    fwrite(&global_state.pt_ip_filter_b, sizeof(uint64_t)*4, 1, fp);

    debug_printf("DUMPING global_state.enable_hprintf: %x\n", global_state.enable_hprintf);
    fwrite(&global_state.enable_hprintf, sizeof(bool), 1, fp);
    debug_printf("DUMPING global_state.parent_cr3: %lx\n", global_state.parent_cr3);
    fwrite(&global_state.parent_cr3, sizeof(uint64_t), 1, fp);
    
    debug_printf("DUMPING global_state.disassembler_word_width: %x\n", global_state.disassembler_word_width);
    fwrite(&global_state.disassembler_word_width, sizeof(uint8_t), 1, fp);
    debug_printf("DUMPING global_state.fast_reload_pre_image: %x\n", global_state.fast_reload_pre_image);
    fwrite(&global_state.fast_reload_pre_image, sizeof(bool), 1, fp);

    debug_printf("DUMPING global_state.mem_mode: %x\n", global_state.mem_mode);
    fwrite(&global_state.mem_mode, sizeof(uint8_t), 1, fp);

    debug_printf("DUMPING global_state.pt_trace_mode: %x\n", global_state.pt_trace_mode);
    fwrite(&global_state.pt_trace_mode, sizeof(bool), 1, fp);

    debug_printf("DUMPING global_state.nested: %x\n", global_state.nested);
    fwrite(&global_state.nested, sizeof(bool), 1, fp);

    if(!global_state.nested){
        debug_printf("DUMPING global_state.payload_buffer: %lx\n", global_state.payload_buffer);
        fwrite(&global_state.payload_buffer, sizeof(uint64_t), 1, fp);

        fwrite(&global_state.cap_timeout_detection, sizeof(global_state.cap_timeout_detection), 1, fp);
        fwrite(&global_state.cap_only_reload_mode, sizeof(global_state.cap_only_reload_mode), 1, fp);
        fwrite(&global_state.cap_compile_time_tracing, sizeof(global_state.cap_compile_time_tracing), 1, fp);
        fwrite(&global_state.cap_ijon_tracing, sizeof(global_state.cap_ijon_tracing), 1, fp);
        fwrite(&global_state.cap_cr3, sizeof(global_state.cap_cr3), 1, fp);
        fwrite(&global_state.cap_compile_time_tracing_buffer_vaddr, sizeof(global_state.cap_compile_time_tracing_buffer_vaddr), 1, fp);
        fwrite(&global_state.cap_ijon_tracing_buffer_vaddr, sizeof(global_state.cap_ijon_tracing_buffer_vaddr), 1, fp);
        fwrite(&global_state.protect_payload_buffer, sizeof(bool), 1, fp);
    }
    else{
        assert(global_state.nested_payload_pages != NULL && global_state.nested_payload_pages_num != 0);
        debug_printf("DUMPING global_state.nested_payload_pages_num: %x\n", global_state.nested_payload_pages_num);
        fwrite(&global_state.nested_payload_pages_num, sizeof(uint32_t), 1, fp);

        if(global_state.nested_payload_pages_num != 0){
            debug_printf("DUMPING global_state.protect_payload_buffer: %x\n", global_state.protect_payload_buffer);
            fwrite(&global_state.protect_payload_buffer, sizeof(bool), 1, fp);
        }

        for(uint32_t i = 0; i < global_state.nested_payload_pages_num; i++){
            debug_printf("DUMPING global_state.nested_payload_pages[%d]: %lx\n", i, global_state.nested_payload_pages[i]);
            fwrite(&global_state.nested_payload_pages[i], sizeof(uint64_t), 1, fp);
        }
    }


    fclose(fp);

	free(tmp);
}

void load_global_state(const char* filename_prefix){
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
    

    assert(fread(&global_state.pt_ip_filter_configured, sizeof(bool)*4, 1, fp) == 1);
    debug_printf("LOADING global_state.pt_ip_filter_configured: -\n");

    assert(fread(&global_state.pt_ip_filter_a, sizeof(uint64_t)*4, 1, fp) == 1);
    debug_printf("LOADING global_state.pt_ip_filter_a: -\n");

    assert(fread(&global_state.pt_ip_filter_b, sizeof(uint64_t)*4, 1, fp) == 1);
    debug_printf("LOADING global_state.pt_ip_filter_b: -\n");

    assert(fread(&global_state.enable_hprintf, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.enable_hprintf: %x\n", global_state.enable_hprintf);

    assert(fread(&global_state.parent_cr3, sizeof(uint64_t), 1, fp) == 1);
    debug_printf("LOADING global_state.parent_cr3: %lx\n", global_state.parent_cr3);

    assert(fread(&global_state.disassembler_word_width, sizeof(uint8_t), 1, fp) == 1);
    debug_printf("LOADING global_state.disassembler_word_width: %x\n", global_state.disassembler_word_width);

    assert(fread(&global_state.fast_reload_pre_image, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.fast_reload_pre_image: %x\n", global_state.fast_reload_pre_image);

    assert(fread(&global_state.mem_mode, sizeof(uint8_t), 1, fp) == 1);
    debug_printf("LOADING global_state.mem_mode: %x\n", global_state.mem_mode);

    assert(fread(&global_state.pt_trace_mode, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.pt_trace_mode: %x\n", global_state.pt_trace_mode);

    assert(fread(&global_state.nested, sizeof(bool), 1, fp) == 1);
    debug_printf("LOADING global_state.nested: %x\n", global_state.nested);

    if(!global_state.nested){
        assert(fread(&global_state.payload_buffer, sizeof(uint64_t), 1, fp) == 1);
        debug_printf("LOADING global_state.payload_buffer: %lx\n", global_state.payload_buffer);

        assert(fread(&global_state.cap_timeout_detection, sizeof(global_state.cap_timeout_detection), 1, fp) == 1);
        assert(fread(&global_state.cap_only_reload_mode, sizeof(global_state.cap_only_reload_mode), 1, fp) == 1);
        assert(fread(&global_state.cap_compile_time_tracing, sizeof(global_state.cap_compile_time_tracing), 1, fp) == 1);
        assert(fread(&global_state.cap_ijon_tracing, sizeof(global_state.cap_ijon_tracing), 1, fp) == 1);
        assert(fread(&global_state.cap_cr3, sizeof(global_state.cap_cr3), 1, fp) == 1);
        assert(fread(&global_state.cap_compile_time_tracing_buffer_vaddr, sizeof(global_state.cap_compile_time_tracing_buffer_vaddr), 1, fp) == 1);
        assert(fread(&global_state.cap_ijon_tracing_buffer_vaddr, sizeof(global_state.cap_ijon_tracing_buffer_vaddr), 1, fp) == 1);

        if(!global_state.fast_reload_pre_image){
            assert(fread(&global_state.protect_payload_buffer, sizeof(bool), 1, fp) == 1);
            if(global_state.payload_buffer != 0){
                debug_printf("REMAP PAYLOAD BUFFER!\n");
                remap_payload_buffer(global_state.payload_buffer, ((CPUState *)qemu_get_cpu(0)) );
            }
            else{
                fprintf(stderr, "WARNING: address of payload buffer in snapshot file is zero!\n");
            }
        }

        apply_capabilities(qemu_get_cpu(0));
    }
    else{
        assert(fread(&global_state.nested_payload_pages_num, sizeof(uint32_t), 1, fp) == 1);
        debug_printf("LOADING global_state.nested_payload_pages_num: %x\n", global_state.nested_payload_pages_num);

        global_state.in_fuzzing_mode = true; /* haaaeeeeh ??? */
        if(!global_state.fast_reload_pre_image){

            assert(fread(&global_state.protect_payload_buffer, sizeof(bool), 1, fp) == 1);
            debug_printf("LOADING global_state.protect_payload_buffer: %x\n", global_state.protect_payload_buffer);

            global_state.nested_payload_pages = (uint64_t*)malloc(sizeof(uint64_t)*global_state.nested_payload_pages_num);
            
            for(uint32_t i = 0; i < global_state.nested_payload_pages_num; i++){
                assert(fread(&global_state.nested_payload_pages[i], sizeof(uint64_t), 1, fp) == 1);
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

static void* alloc_auxiliary_buffer(const char* file){
	void* ptr;
	struct stat st;
	int fd = open(file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, AUX_BUFFER_SIZE) == 0);
	stat(file, &st);
	QEMU_PT_PRINTF(INTERFACE_PREFIX, "new aux buffer file: (max size: %x) %lx", AUX_BUFFER_SIZE, st.st_size);
	
	assert(AUX_BUFFER_SIZE == st.st_size);
	ptr = mmap(0, AUX_BUFFER_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		fprintf(stderr, "aux buffer allocation failed!\n");
		return (void*)-1;
	}
	return ptr;
}

void init_aux_buffer(const char* filename){
    global_state.auxilary_buffer = (auxilary_buffer_t*)alloc_auxiliary_buffer(filename);
    init_auxiliary_buffer(global_state.auxilary_buffer);
}

void set_payload_buffer(uint64_t payload_buffer){
    assert(global_state.payload_buffer == 0 && global_state.nested == false);
    global_state.payload_buffer = payload_buffer;
    global_state.nested = false;
}

void set_payload_pages(uint64_t* payload_pages, uint32_t pages){
    assert(global_state.nested_payload_pages == NULL && global_state.nested_payload_pages_num == 0);
    global_state.nested_payload_pages = (uint64_t*)malloc(sizeof(uint64_t)*pages);
    global_state.nested_payload_pages_num = pages;
    memcpy(global_state.nested_payload_pages, payload_pages, sizeof(uint64_t)*pages);
    global_state.nested = true;
}

void set_workdir_path(char* workdir){
    assert(workdir && !global_state.workdir_path);
	assert(asprintf(&global_state.workdir_path, "%s", workdir) != -1);
}