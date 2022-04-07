#pragma once

#include "qemu/osdep.h"
#include <stdint.h>

void handle_hypercall_kafl_get_host_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);
void handle_hypercall_kafl_set_agent_config(struct kvm_run *run, CPUState *cpu, uint64_t hypercall_arg);


#define NYX_HOST_MAGIC  0x4878794e
#define NYX_AGENT_MAGIC 0x4178794e

#define NYX_HOST_VERSION 2 
#define NYX_AGENT_VERSION 1

typedef struct host_config_s{
  uint32_t host_magic;
  uint32_t host_version;
  uint32_t bitmap_size;
  uint32_t ijon_bitmap_size;
	uint32_t payload_buffer_size;
  uint32_t worker_id;
  /* more to come */
} __attribute__((packed)) host_config_t;

typedef struct agent_config_s{
  uint32_t agent_magic;
  uint32_t agent_version;
  uint8_t agent_timeout_detection;
  uint8_t agent_tracing;
  uint8_t agent_ijon_tracing;
	uint8_t agent_non_reload_mode;
	uint64_t trace_buffer_vaddr;
	uint64_t ijon_trace_buffer_vaddr;
  
	uint32_t coverage_bitmap_size;
	uint32_t input_buffer_size;

  uint8_t dump_payloads; /* set by hypervisor */
  /* more to come */
} __attribute__((packed)) agent_config_t;
