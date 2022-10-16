#pragma once

#include "nyx/fast_vm_reload.h"
#include <stdint.h>

void     nyx_snapshot_debug_pre_init(void);
void     nyx_snapshot_debug_init(fast_reload_t *self);
void     nyx_snapshot_debug_enable(fast_reload_t *self);
uint32_t nyx_snapshot_debug_restore(shadow_memory_t           *shadow_memory_state,
                                    snapshot_page_blocklist_t *blocklist,
                                    bool                       verbose);
void     nyx_snapshot_debug_set(fast_reload_t *self);
void     nyx_snapshot_debug_save_root_pages(shadow_memory_t *shadow_memory_state,
                                            snapshot_page_blocklist_t *blocklist,
                                            bool                       verbose);
