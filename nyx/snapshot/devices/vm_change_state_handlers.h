#pragma once

#include "sysemu/runstate.h"
#include <stdint.h>
#include <stdlib.h>

#define RELOAD_HANDLER_KVM_CLOCK 0
#define RELOAD_HANDLER_KVM_PIT   1
#define RELOAD_HANDLER_KVM_CPU   2
#define RELOAD_HANDLER_IDE_CORE  3

void call_fast_change_handlers(void);
void add_fast_reload_change_handler(VMChangeStateHandler *cb, void *opaque, int id);
