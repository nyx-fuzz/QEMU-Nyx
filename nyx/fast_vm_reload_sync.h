#pragma once

#include <stdbool.h>

typedef enum FastReloadRequest {
    REQUEST_VOID,

    /* create snapshots */
    REQUEST_SAVE_SNAPSHOT_PRE,
    REQUEST_SAVE_SNAPSHOT_ROOT,
    REQUEST_SAVE_SNAPSHOT_TMP,

    /* create snapshot and fix RIP (- sizeof(vmcall)) */
    REQUEST_SAVE_SNAPSHOT_PRE_FIX_RIP,
    REQUEST_SAVE_SNAPSHOT_ROOT_FIX_RIP,
    REQUEST_SAVE_SNAPSHOT_TMP_FIX_RIP,

    /* create nested snapshots */
    REQUEST_SAVE_SNAPSHOT_ROOT_NESTED_FIX_RIP,
    REQUEST_SAVE_SNAPSHOT_TMP_NESTED_FIX_RIP,

    /* load snapshots*/
    REQUEST_LOAD_SNAPSHOT_PRE,
    REQUEST_LOAD_SNAPSHOT_ROOT,
    REQUEST_LOAD_SNAPSHOT_TMP,

    /* check if snapshot exists */
    REQUEST_PRE_EXISTS,
    REQUEST_ROOT_EXISTS,
    REQUEST_TMP_EXISTS,

    // REQUEST_DISCARD_SNAPSHOT_TMP,
} FastReloadRequest;

typedef enum FastReloadMode {
    RELOAD_MODE_DEBUG, /* savevm / loadvm based on QEMU's qcow2 storage - only for debug purposes */
    RELOAD_MODE_NO_BLOCK, /* fastest mode - works only if no active block devices is attached (e.g. initramfs mode) */
    RELOAD_MODE_BLOCK,
} FastReloadMode;


typedef struct fast_vm_reload_sync_s {
    bool              request_exists;
    bool              request_exists_pre;
    bool              debug_mode;
    FastReloadMode    mode;
    FastReloadRequest current_request;
} fast_vm_reload_sync_t;


fast_vm_reload_sync_t *init_fast_vm_reload_sync(void);
void request_fast_vm_reload(fast_vm_reload_sync_t *self, FastReloadRequest request);
bool reload_request_exists(fast_vm_reload_sync_t *self);
bool check_if_relood_request_exists_pre(fast_vm_reload_sync_t *self);
bool check_if_relood_request_exists_post(fast_vm_reload_sync_t *self);


bool fast_snapshot_exists(fast_vm_reload_sync_t *self, FastReloadRequest type);
void reload_request_discard_tmp(fast_vm_reload_sync_t *self);