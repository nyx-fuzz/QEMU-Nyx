#pragma once 

#include <stdint.h>
#include <stdbool.h>
#include "nyx/snapshot/devices/state_reallocation.h"

typedef struct nyx_device_state_s{
  state_reallocation_t* qemu_state;

  uint64_t tsc_value;
	uint64_t tsc_value_incremental;

  bool incremental_mode;

  void* state_buf; /* QEMU's serialized state */
	uint32_t state_buf_size;

} nyx_device_state_t; 


nyx_device_state_t* nyx_device_state_init(void);
nyx_device_state_t* nyx_device_state_init_from_snapshot(const char* snapshot_folder, bool pre_snapshot);

void nyx_device_state_restore(nyx_device_state_t* self);
void nyx_device_state_post_restore(nyx_device_state_t* self);

void nyx_device_state_switch_incremental(nyx_device_state_t* self);
void nyx_device_state_disable_incremental(nyx_device_state_t* self);

void nyx_device_state_save_tsc(nyx_device_state_t* self);
void nyx_device_state_save_tsc_incremental(nyx_device_state_t* self);

void nyx_device_state_serialize(nyx_device_state_t* self, const char* snapshot_folder);
