#pragma once

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/log.h"
#include "qemu-common.h"

#define ENABLE_BACKTRACES

#define NYX_LOG_PREFIX    "[QEMU-NYX] "
#define CORE_PREFIX       "Core:      "
#define MEM_PREFIX        "Memory:    "
#define RELOAD_PREFIX     "Reload:    "
#define PT_PREFIX         "PT:        "
#define INTERFACE_PREFIX  "Interface: "
#define REDQUEEN_PREFIX   "Redqueen:  "
#define DISASM_PREFIX     "Disasm:    "
#define PAGE_CACHE_PREFIX "PageCache: "
#define NESTED_VM_PREFIX  "Nested:    "

#ifdef NYX_DEBUG
/*
 * qemu_log() is the standard logging enabled with -D
 * qemu_log_mask() is activated with additional -t nyx option
 */
// #define nyx_debug(format, ...)         qemu_log_mask(LOG_NYX, NYX_LOG_PREFIX
// "(%s#:%d)\t"format, __BASE_FILE__, __LINE__, ##__VA_ARGS__)
#define nyx_debug(format, ...) \
    qemu_log_mask(LOG_NYX, NYX_LOG_PREFIX format, ##__VA_ARGS__)
#define nyx_debug_p(PREFIX, format, ...) \
    qemu_log_mask(LOG_NYX, NYX_LOG_PREFIX PREFIX format, ##__VA_ARGS__)
#else
#define nyx_debug(...)
#define nyx_debug_p(...)
#endif

#define nyx_printf(format, ...) qemu_log(format, ##__VA_ARGS__)
#define nyx_error(format, ...)  error_printf(format, ##__VA_ARGS__)
#define nyx_trace(format, ...)  nyx_debug("=> %s\n", __func__)

#ifdef ENABLE_BACKTRACES
void qemu_backtrace(void);
void init_crash_handler(void);
void hexdump_kafl(const void *data, size_t size);
#endif
