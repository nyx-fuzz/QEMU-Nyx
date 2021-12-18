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

#pragma once
#include <stdint.h>
#include <stdbool.h>

#define AUX_BUFFER_SIZE 4096

#define AUX_MAGIC 0x54502d554d4551

#define QEMU_PT_VERSION 2 /* let's start at 1 for the initial version using the aux buffer */

#define HEADER_SIZE 128
#define CAP_SIZE 256
#define CONFIG_SIZE 512
#define STATE_SIZE 512
#define MISC_SIZE 4096-(HEADER_SIZE+CAP_SIZE+CONFIG_SIZE+STATE_SIZE)

#define ADD_PADDING(max, type) uint8_t type ## _padding [max - sizeof(type)]

typedef struct auxilary_buffer_header_s{
  uint64_t magic;   /* 0x54502d554d4551 */
  uint16_t version; 
  uint16_t hash; 
  /* more to come */
} __attribute__((packed)) auxilary_buffer_header_t;

typedef struct auxilary_buffer_cap_s{
  uint8_t redqueen;
  uint8_t agent_timeout_detection;  /* agent implements own timeout detection; host timeout detection is still in used, but treshold is increased by x2; */
  uint8_t agent_trace_bitmap;       /* agent implements own tracing mechanism; PT tracing is disabled */
  uint8_t agent_ijon_trace_bitmap;  /* agent uses the ijon shm buffer */

  /* more to come */
} __attribute__((packed)) auxilary_buffer_cap_t;

typedef struct auxilary_buffer_config_s{
  uint8_t changed;  /* set this byte to kick in a rescan of this buffer */

  uint8_t timeout_sec;
  uint32_t timeout_usec;

  /* trigger to enable / disable different QEMU-PT modes */
  uint8_t redqueen_mode; 
  uint8_t trace_mode; 
  uint8_t reload_mode;

  uint8_t verbose_level;

  uint8_t page_dump_mode;
  uint64_t page_addr; 

  /* nested mode only */
  uint8_t protect_payload_buffer; 

  /*  0 -> disabled
      1 -> decoding
      2 -> decoding + full disassembling
  */
  //uint8_t pt_processing_mode; 

  /* snapshot extension */
  uint8_t discard_tmp_snapshot;

  /* more to come */
} __attribute__((packed)) auxilary_buffer_config_t;

typedef struct auxilary_buffer_result_s{
  /*  0 -> booting, 
      1 -> loader level 1, 
      2 -> loader level 2, 
      3 -> ready to fuzz
  */
  uint8_t state; 
  /* snapshot extension */
  uint8_t tmp_snapshot_created;

  /* FML */
  uint8_t padding_1;
  uint8_t padding_2;

  uint32_t bb_coverage; 

  uint8_t padding_3;
  uint8_t padding_4;

  uint8_t hprintf;
  uint8_t exec_done; 

  uint8_t crash_found; 
  uint8_t asan_found; 

  uint8_t timeout_found; 
  uint8_t reloaded;

  uint8_t pt_overflow;
  uint8_t runtime_sec;
  
  uint8_t page_not_found;
  uint8_t success;

  uint32_t runtime_usec;
  uint64_t page_addr; 
  uint32_t dirty_pages; 
  uint32_t pt_trace_size; 

  uint8_t payload_buffer_write_attempt_found;
  uint8_t abort; 

  /* more to come */
} __attribute__((packed)) auxilary_buffer_result_t;

typedef struct auxilary_buffer_misc_s{
  uint16_t len;
  uint8_t data;
  /* non yet */
} __attribute__((packed)) auxilary_buffer_misc_t;

typedef struct auxilary_buffer_s{
  auxilary_buffer_header_t header;
  ADD_PADDING(HEADER_SIZE, auxilary_buffer_header_t);

  auxilary_buffer_cap_t capabilites;
  ADD_PADDING(CAP_SIZE, auxilary_buffer_cap_t);

  auxilary_buffer_config_t configuration;
  ADD_PADDING(CONFIG_SIZE, auxilary_buffer_config_t);

  auxilary_buffer_result_t result;
  ADD_PADDING(STATE_SIZE, auxilary_buffer_result_t);

  auxilary_buffer_misc_t misc;
  ADD_PADDING(MISC_SIZE, auxilary_buffer_misc_t);

} __attribute__((packed)) auxilary_buffer_t;

void init_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer);
void check_auxiliary_config_buffer(auxilary_buffer_t* auxilary_buffer, auxilary_buffer_config_t* shadow_config);

void flush_hprintf_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer);

void set_crash_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer);
void set_asan_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer);
void set_timeout_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer);
void set_reload_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer);
void set_pt_overflow_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer);
void flush_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer);
void set_exec_done_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer, uint8_t sec, uint32_t usec);
void set_state_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer, uint8_t state);
void set_hprintf_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len);

void set_page_not_found_result_buffer(auxilary_buffer_t* auxilary_buffer, uint64_t page_addr);
void set_success_auxiliary_result_buffer(auxilary_buffer_t* auxilary_buffer, uint8_t success);
void set_crash_reason_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len);
void set_abort_reason_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len);

void set_tmp_snapshot_created(auxilary_buffer_t* auxilary_buffer, uint8_t value);

void set_cap_agent_trace_bitmap(auxilary_buffer_t* auxilary_buffer, bool value);
void set_cap_agent_ijon_trace_bitmap(auxilary_buffer_t* auxilary_buffer, bool value);


void set_result_dirty_pages(auxilary_buffer_t* auxilary_buffer, uint32_t value);
void set_result_pt_trace_size(auxilary_buffer_t* auxilary_buffer, uint32_t value);

void set_result_bb_coverage(auxilary_buffer_t* auxilary_buffer, uint32_t value);

void set_payload_buffer_write_reason_auxiliary_buffer(auxilary_buffer_t* auxilary_buffer, char* msg, uint32_t len);