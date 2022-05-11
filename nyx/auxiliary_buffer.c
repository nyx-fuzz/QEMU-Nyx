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

#include "nyx/auxiliary_buffer.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "nyx/state/state.h"
#include "nyx/debug.h"
#include "nyx/trace_dump.h"

/* experimental feature (currently broken)
 * enabled via trace mode
 */
//#define SUPPORT_COMPILE_TIME_REDQUEEN

#define VOLATILE_WRITE_64(dst, src) *((volatile uint64_t*)&dst) = (uint64_t)src
#define VOLATILE_WRITE_32(dst, src) *((volatile uint32_t*)&dst) = (uint32_t)src
#define VOLATILE_WRITE_16(dst, src) *((volatile uint16_t*)&dst) = (uint16_t)src
#define VOLATILE_WRITE_8(dst, src) *((volatile uint8_t*)&dst) = (uint8_t)src

#define VOLATILE_READ_64(dst, src) dst = *((volatile uint64_t*)(&src)) 
#define VOLATILE_READ_32(dst, src) dst = *((volatile uint32_t*)(&src)) 
#define VOLATILE_READ_16(dst, src) dst = *((volatile uint16_t*)(&src)) 
#define VOLATILE_READ_8(dst, src) dst = *((volatile uint8_t*)(&src)) 

static void volatile_memset(void* dst, uint8_t ch, size_t count){
  for (size_t i = 0; i < count; i++){
    VOLATILE_WRITE_8(((uint8_t*)dst)[i], ch);
  }
}

static void volatile_memcpy(void* dst, void* src, size_t size){
  for (size_t i = 0; i < size; i++){
    VOLATILE_WRITE_8(((uint8_t*)dst)[i], ((uint8_t*)src)[i]);
  }
}

void init_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer){
  debug_fprintf(stderr, "%s\n", __func__);
  volatile_memset((void*) auxilary_buffer, 0, sizeof(auxilary_buffer_t));

  VOLATILE_WRITE_16(auxilary_buffer->header.version, QEMU_PT_VERSION);

  uint16_t hash = (sizeof(auxilary_buffer_header_t) + 
                  sizeof(auxilary_buffer_cap_t) + 
                  sizeof(auxilary_buffer_config_t) + 
                  sizeof(auxilary_buffer_result_t) + 
                  sizeof(auxilary_buffer_misc_t)) % 0xFFFF;

  VOLATILE_WRITE_16(auxilary_buffer->header.hash, hash);

  VOLATILE_WRITE_64(auxilary_buffer->header.magic, AUX_MAGIC);               
}

void check_auxiliary_config_buffer(auxilary_buffer_t* auxilary_buffer, auxilary_buffer_config_t* shadow_config){
  uint8_t changed = 0;
  VOLATILE_READ_8(changed, auxilary_buffer->configuration.changed);
  if (changed){

  
    uint8_t aux_byte;

    VOLATILE_READ_8(aux_byte, auxilary_buffer->configuration.redqueen_mode);
    if(aux_byte){
      /* enable redqueen mode */
      if(aux_byte != shadow_config->redqueen_mode){
        GET_GLOBAL_STATE()->in_redqueen_reload_mode = true;
        GET_GLOBAL_STATE()->redqueen_enable_pending = true;
	      GET_GLOBAL_STATE()->redqueen_instrumentation_mode = REDQUEEN_LIGHT_INSTRUMENTATION;
      }
    }
    else{
      /* disable redqueen mode */
      if(aux_byte != shadow_config->redqueen_mode){
        GET_GLOBAL_STATE()->in_redqueen_reload_mode = false;
        GET_GLOBAL_STATE()->redqueen_disable_pending = true;
	      GET_GLOBAL_STATE()->redqueen_instrumentation_mode = REDQUEEN_NO_INSTRUMENTATION;
      }
    }

    VOLATILE_READ_8(aux_byte, auxilary_buffer->configuration.trace_mode);
    if(aux_byte){
      /* enable trace mode */
      if(aux_byte != shadow_config->trace_mode && GET_GLOBAL_STATE()->redqueen_state){
#ifdef SUPPORT_COMPILE_TIME_REDQUEEN
        GET_GLOBAL_STATE()->pt_trace_mode_force = true;		  
#endif
		GET_GLOBAL_STATE()->trace_mode = true;
        redqueen_set_trace_mode();
        pt_trace_dump_enable(true);
      }
    }
    else {
      /* disable trace mode */
      if(aux_byte != shadow_config->trace_mode && GET_GLOBAL_STATE()->redqueen_state){
#ifdef SUPPORT_COMPILE_TIME_REDQUEEN
        GET_GLOBAL_STATE()->pt_trace_mode_force = false;
#endif
		GET_GLOBAL_STATE()->trace_mode = false;
        redqueen_unset_trace_mode();
        pt_trace_dump_enable(false);
      }
    }

    VOLATILE_READ_8(aux_byte, auxilary_buffer->configuration.page_dump_mode);
    if(aux_byte){
      GET_GLOBAL_STATE()->dump_page = true;
      uint64_t data;
      VOLATILE_READ_64(data, auxilary_buffer->configuration.page_addr);
      GET_GLOBAL_STATE()->dump_page_addr = data;
      //fprintf(stderr, "%s dump_page_addr => 0x%lx\n", __func__, GET_GLOBAL_STATE()->dump_page_addr);
      VOLATILE_WRITE_8(auxilary_buffer->configuration.page_dump_mode, 0);
      VOLATILE_WRITE_64(auxilary_buffer->configuration.page_addr, 0);
    }

    /* modify reload mode */
    VOLATILE_READ_8(aux_byte, auxilary_buffer->configuration.reload_mode);
    GET_GLOBAL_STATE()->in_reload_mode = aux_byte;

    /* modify protect_payload_buffer */
    VOLATILE_READ_8(aux_byte, auxilary_buffer->configuration.protect_payload_buffer);
    if (GET_GLOBAL_STATE()->protect_payload_buffer == 0 && aux_byte == 1){
      GET_GLOBAL_STATE()->protect_payload_buffer = aux_byte;
    }

    /* modify protect_payload_buffer */
    VOLATILE_READ_8(aux_byte, auxilary_buffer->configuration.discard_tmp_snapshot);
    GET_GLOBAL_STATE()->discard_tmp_snapshot = aux_byte;
    VOLATILE_WRITE_8(auxilary_buffer->configuration.discard_tmp_snapshot, 0);
    
    /* copy to shodow */
    VOLATILE_READ_8(shadow_config->timeout_sec, auxilary_buffer->configuration.timeout_sec);
    VOLATILE_READ_32(shadow_config->timeout_usec, auxilary_buffer->configuration.timeout_usec);

    //if(shadow_config->timeout_sec || shadow_config->timeout_usec){
      /* apply only non-zero values */
      update_itimer(&(GET_GLOBAL_STATE()->timeout_detector), shadow_config->timeout_sec, shadow_config->timeout_usec);
    //}

    VOLATILE_READ_8(shadow_config->redqueen_mode, auxilary_buffer->configuration.redqueen_mode);
    VOLATILE_READ_8(shadow_config->trace_mode, auxilary_buffer->configuration.trace_mode);
    VOLATILE_READ_8(shadow_config->reload_mode, auxilary_buffer->configuration.reload_mode);

    VOLATILE_READ_8(shadow_config->verbose_level, auxilary_buffer->configuration.verbose_level);

    /* reset the 'changed' byte */
    VOLATILE_WRITE_8(auxilary_buffer->configuration.changed, 0);
  }
}

void set_crash_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer){
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_crash);
}

void set_asan_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer){
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_sanitizer);
}

void set_timeout_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer){
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_timeout);
}

void set_reload_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer){
  VOLATILE_WRITE_8(auxilary_buffer->result.reloaded, 1);
}

void set_pt_overflow_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer){
  VOLATILE_WRITE_8(auxilary_buffer->result.pt_overflow, 1);
}

void set_exec_done_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer, uint32_t sec, uint32_t usec, uint32_t num_dirty_pages){
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_done, 1);

  VOLATILE_WRITE_32(auxilary_buffer->result.runtime_sec, sec);
  VOLATILE_WRITE_32(auxilary_buffer->result.runtime_usec, usec);
  VOLATILE_WRITE_32(auxilary_buffer->result.dirty_pages, num_dirty_pages);
}



void set_hprintf_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len){
  VOLATILE_WRITE_16(auxilary_buffer->misc.len, MIN(len, MISC_SIZE-2));
  volatile_memcpy((void*)&auxilary_buffer->misc.data, (void*)msg, (size_t)MIN(len, MISC_SIZE-2));
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_hprintf);
}

void set_crash_reason_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len){
  VOLATILE_WRITE_16(auxilary_buffer->misc.len, MIN(len, MISC_SIZE-2));
  volatile_memcpy((void*)&auxilary_buffer->misc.data, (void*)msg, (size_t) MIN(len, MISC_SIZE-2));
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_crash);
}

void set_abort_reason_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len){
  VOLATILE_WRITE_16(auxilary_buffer->misc.len, MIN(len, MISC_SIZE-2));
  volatile_memcpy((void*)&auxilary_buffer->misc.data, (void*)msg, (size_t) MIN(len, MISC_SIZE-2));
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_aborted);
}

void set_state_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer, uint8_t state){
  if(auxilary_buffer){
    VOLATILE_WRITE_8(auxilary_buffer->result.state, state);
  }
  else{
    fprintf(stderr, "WARNING: auxilary_buffer pointer is zero\n");
  }
}

void set_page_not_found_result_buffer(auxilary_buffer_t* auxilary_buffer, uint64_t page_addr){
  VOLATILE_WRITE_8(auxilary_buffer->result.page_not_found, 1);
  VOLATILE_WRITE_64(auxilary_buffer->result.page_addr, page_addr);
}

void reset_page_not_found_result_buffer(auxilary_buffer_t* auxilary_buffer){
  VOLATILE_WRITE_8(auxilary_buffer->result.page_not_found, 0);
}

void set_success_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer, uint8_t success){
  //should refactor to let caller directly set the result codes
  if (success == 2) {
	  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_starved);
  } else {
	  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_success);
  }
}

void set_payload_buffer_write_reason_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len){
  VOLATILE_WRITE_16(auxilary_buffer->misc.len, MIN(len, MISC_SIZE-2));
  volatile_memcpy((void*)&auxilary_buffer->misc.data, (void*)msg, (size_t) MIN(len, MISC_SIZE-2));
  VOLATILE_WRITE_8(auxilary_buffer->result.exec_result_code, rc_input_buffer_write);
}


void set_tmp_snapshot_created(auxilary_buffer_t* auxilary_buffer, uint8_t value){
  VOLATILE_WRITE_8(auxilary_buffer->result.tmp_snapshot_created, value);
}

void set_cap_agent_trace_bitmap(auxilary_buffer_t* auxilary_buffer, bool value){
  VOLATILE_WRITE_8(auxilary_buffer->capabilites.agent_trace_bitmap, value);
}

void set_cap_agent_ijon_trace_bitmap(auxilary_buffer_t* auxilary_buffer, bool value){
  VOLATILE_WRITE_8(auxilary_buffer->capabilites.agent_ijon_trace_bitmap, value);
}

void set_result_dirty_pages(auxilary_buffer_t* auxilary_buffer, uint32_t value){
  VOLATILE_WRITE_32(auxilary_buffer->result.dirty_pages, value);
}

void set_result_pt_trace_size(auxilary_buffer_t* auxilary_buffer, uint32_t value){
  VOLATILE_WRITE_32(auxilary_buffer->result.pt_trace_size, value);
}

void set_result_bb_coverage(auxilary_buffer_t* auxilary_buffer, uint32_t value){
  if (value != auxilary_buffer->result.bb_coverage){
    VOLATILE_WRITE_32(auxilary_buffer->result.bb_coverage, value);
  }
}
