#pragma once

#include "sysemu/kvm.h"
#include "nyx/patcher.h"

void pt_enable_patches(patcher_t *self);

void pt_disable_patches(patcher_t *self);
