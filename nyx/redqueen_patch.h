#ifndef __GUARD_REDQUEEN_PATCH__
#define __GUARD_REDQUEEN_PATCH__

#include "qemu/osdep.h"
#include <linux/kvm.h>
#include "nyx/patcher.h"

void pt_enable_patches(patcher_t *self);

void pt_disable_patches(patcher_t *self);
#endif
