#include <stdio.h>
#include <stdint.h>
#include "nyx/helpers.h"
#include "qemu/osdep.h"
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "qemu-common.h"
#include "exec/memory.h"
#include "qemu/main-loop.h"
#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "nyx/state/state.h"
#include "nyx/memory_access.h"
#include "nyx/debug.h"
#include "nyx/helpers.h"

void nyx_abort(char* msg){
	set_abort_reason_auxiliary_buffer(GET_GLOBAL_STATE()->auxilary_buffer, msg, strlen(msg));
	synchronization_lock();
	exit(1);
}

bool is_called_in_fuzzing_mode(const char* hypercall){
	if(GET_GLOBAL_STATE()->in_fuzzing_mode){
		char* tmp = NULL;
		assert(asprintf(&tmp, "Hypercall <%s> called during fuzzing...", hypercall) != -1);
		nyx_abort((char*)tmp);
		free(tmp);
		return true;
	}
	return false;
}

uint64_t get_rip(CPUState *cpu){
	kvm_arch_get_registers(cpu);
	X86CPU *x86_cpu = X86_CPU(cpu);
	CPUX86State *env = &x86_cpu->env;
	kvm_cpu_synchronize_state(cpu);
	return env->eip;
}

int get_capstone_mode(int word_width_in_bits){
	switch(word_width_in_bits){
		case 64: 
			return CS_MODE_64;
		case 32: 
			return CS_MODE_32;
		default:
			assert(false);
	}
}

nyx_coverage_bitmap_copy_t* new_coverage_bitmaps(void){
	nyx_coverage_bitmap_copy_t* bitmaps = malloc(sizeof(nyx_coverage_bitmap_copy_t));
	memset(bitmaps, 0, sizeof(nyx_coverage_bitmap_copy_t));

	assert(GET_GLOBAL_STATE()->shared_bitmap_size);
	bitmaps->coverage_bitmap = malloc(GET_GLOBAL_STATE()->shared_bitmap_size);

	assert(GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
	bitmaps->ijon_bitmap_buffer = malloc(GET_GLOBAL_STATE()->shared_ijon_bitmap_size);

	return bitmaps;
}

void coverage_bitmap_reset(void){
	if(GET_GLOBAL_STATE()->shared_bitmap_ptr){
		memset(GET_GLOBAL_STATE()->shared_bitmap_ptr, 0x00, GET_GLOBAL_STATE()->shared_bitmap_real_size);
	}
	if (GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr && GET_GLOBAL_STATE()->shared_ijon_bitmap_size){
		memset(GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr, 0x00, GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
	}
}

void coverage_bitmap_copy_to_buffer(nyx_coverage_bitmap_copy_t* buffer){

	if(GET_GLOBAL_STATE()->shared_bitmap_ptr){
		memcpy(buffer->coverage_bitmap, GET_GLOBAL_STATE()->shared_bitmap_ptr, GET_GLOBAL_STATE()->shared_bitmap_real_size);
	}
	if (GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr){
		memcpy(buffer->ijon_bitmap_buffer, GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr, GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
	}
}

void coverage_bitmap_copy_from_buffer(nyx_coverage_bitmap_copy_t* buffer){

	if(GET_GLOBAL_STATE()->shared_bitmap_ptr){
		memcpy(GET_GLOBAL_STATE()->shared_bitmap_ptr, buffer->coverage_bitmap, GET_GLOBAL_STATE()->shared_bitmap_real_size);
	}
	if (GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr){
		memcpy(GET_GLOBAL_STATE()->shared_ijon_bitmap_ptr, buffer->ijon_bitmap_buffer, GET_GLOBAL_STATE()->shared_ijon_bitmap_size);
	}
}

static void resize_coverage_bitmap(uint32_t new_bitmap_size){
	uint32_t new_bitmap_shm_size = new_bitmap_size;

	if (new_bitmap_shm_size % 64 > 0) {
    	new_bitmap_shm_size = ((new_bitmap_shm_size + 64) >> 6) << 6;
    }

	GET_GLOBAL_STATE()->shared_bitmap_real_size = new_bitmap_shm_size;
	resize_shared_memory(new_bitmap_shm_size, &GET_GLOBAL_STATE()->shared_bitmap_size, &GET_GLOBAL_STATE()->shared_bitmap_ptr, GET_GLOBAL_STATE()->shared_bitmap_fd);

	/* pass the actual bitmap buffer size to the front-end */
	GET_GLOBAL_STATE()->auxilary_buffer->capabilites.agent_coverage_bitmap_size = new_bitmap_size;

	if(new_bitmap_size & (PAGE_SIZE-1)){
        GET_GLOBAL_STATE()->shared_bitmap_size = (new_bitmap_size & ~(PAGE_SIZE-1)) + PAGE_SIZE;
    }
}

bool apply_capabilities(CPUState *cpu){
	//X86CPU *cpux86 = X86_CPU(cpu);
  //CPUX86State *env = &cpux86->env;

	debug_fprintf(stderr, "%s: agent supports timeout detection: %d\n", __func__, GET_GLOBAL_STATE()->cap_timeout_detection);
	debug_fprintf(stderr, "%s: agent supports only-reload mode: %d\n", __func__, GET_GLOBAL_STATE()->cap_only_reload_mode);
	debug_fprintf(stderr, "%s: agent supports compile-time tracing: %d\n", __func__, GET_GLOBAL_STATE()->cap_compile_time_tracing );

	if(GET_GLOBAL_STATE()->cap_compile_time_tracing){
		GET_GLOBAL_STATE()->pt_trace_mode = false;

		debug_fprintf(stderr, "%s: agent trace buffer at vaddr: %lx\n", __func__, GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr);
		kvm_arch_get_registers_fast(cpu);

		debug_printf("--------------------------\n");
		debug_printf("GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr: %lx\n", GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr);
		debug_printf("GET_GLOBAL_STATE()->shared_bitmap_fd: %lx\n", GET_GLOBAL_STATE()->shared_bitmap_fd);
		debug_printf("GET_GLOBAL_STATE()->shared_bitmap_size: %lx\n", GET_GLOBAL_STATE()->shared_bitmap_size);
		debug_printf("GET_GLOBAL_STATE()->cap_cr3: %lx\n", GET_GLOBAL_STATE()->cap_cr3);
		debug_printf("--------------------------\n");

		if (GET_GLOBAL_STATE()->input_buffer_size != GET_GLOBAL_STATE()->shared_payload_buffer_size){
			resize_shared_memory(GET_GLOBAL_STATE()->input_buffer_size, &GET_GLOBAL_STATE()->shared_payload_buffer_size, NULL, GET_GLOBAL_STATE()->shared_payload_buffer_fd);
			GET_GLOBAL_STATE()->shared_payload_buffer_size = GET_GLOBAL_STATE()->input_buffer_size;
		}

		if(GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr&0xfff){
			fprintf(stderr, "[QEMU-Nyx] Error: guest's trace bitmap v_addr (0x%lx) is not page aligned!\n", GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr);
			return false;
		}

		if (GET_GLOBAL_STATE()->cap_coverage_bitmap_size){
			resize_coverage_bitmap(GET_GLOBAL_STATE()->cap_coverage_bitmap_size);
		}
		
		for(uint64_t i = 0; i < GET_GLOBAL_STATE()->shared_bitmap_size; i += 0x1000){
			assert(remap_slot(GET_GLOBAL_STATE()->cap_compile_time_tracing_buffer_vaddr+ i, i/0x1000, cpu, GET_GLOBAL_STATE()->shared_bitmap_fd, GET_GLOBAL_STATE()->shared_bitmap_size, true, GET_GLOBAL_STATE()->cap_cr3));
		}
		set_cap_agent_trace_bitmap(GET_GLOBAL_STATE()->auxilary_buffer, true);
	}
	
	if(GET_GLOBAL_STATE()->cap_ijon_tracing){
		debug_printf(stderr, "%s: agent trace buffer at vaddr: %lx\n", __func__, GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr);

		if(GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr&0xfff){
			fprintf(stderr, "[QEMU-Nyx] Error: guest's ijon buffer v_addr (0x%lx) is not page aligned!\n", GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr);
			return false;
		}

		kvm_arch_get_registers_fast(cpu);
		for(uint64_t i = 0; i < GET_GLOBAL_STATE()->shared_ijon_bitmap_size; i += 0x1000){
			assert(remap_slot(GET_GLOBAL_STATE()->cap_ijon_tracing_buffer_vaddr + i, i/0x1000, cpu, GET_GLOBAL_STATE()->shared_ijon_bitmap_fd, GET_GLOBAL_STATE()->shared_ijon_bitmap_size+GET_GLOBAL_STATE()->shared_ijon_bitmap_size, true, GET_GLOBAL_STATE()->cap_cr3));
		}
		set_cap_agent_ijon_trace_bitmap(GET_GLOBAL_STATE()->auxilary_buffer, true);
	}


	/* pass the actual input buffer size to the front-end */
	GET_GLOBAL_STATE()->auxilary_buffer->capabilites.agent_input_buffer_size = GET_GLOBAL_STATE()->shared_payload_buffer_size;

	return true;
}

bool folder_exits(const char* path){
	struct stat sb;
	return (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode));
}

bool file_exits(const char* path){
	struct stat sb;   
	return (stat (path, &sb) == 0);
}
