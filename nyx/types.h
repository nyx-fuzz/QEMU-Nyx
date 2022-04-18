#pragma once

enum mem_mode { 
    mm_unkown,
	mm_32_protected,    /* 32 Bit / No MMU */
	mm_32_paging,       /* 32 Bit / L3 Paging */
	mm_32_pae,          /* 32 Bit / PAE Paging */
	mm_64_l4_paging,    /* 64 Bit / L4 Paging */
	mm_64_l5_paging,    /* 32 Bit / L5 Paging */
};

typedef uint8_t mem_mode_t;


#define NYX_HOST_MAGIC  0x4878794e
#define NYX_AGENT_MAGIC 0x4178794e

#define NYX_HOST_VERSION 2 
#define NYX_AGENT_VERSION 2

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

	uint64_t pt_cr3_mode_value;		/* either an offset or an absolute address */
	uint8_t pt_cr3_mode;

	uint8_t dump_payloads; /* set by hypervisor */
	/* more to come */
} __attribute__((packed)) agent_config_t;

enum nyx_cr3_mode { 
    cr3_current,			/* current cr3 value */
	cr3_current_offset,		/* current cr3 + offset taken from agent_config */
	cr3_absolute,			/* absolute cr3 value taken from agent_config */
};
