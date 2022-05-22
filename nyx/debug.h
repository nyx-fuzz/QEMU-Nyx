#pragma once

#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/log.h"

#define ENABLE_BACKTRACES

#define QEMU_PT_PRINT_PREFIX  "[QEMU-NYX] "
#define CORE_PREFIX           "Core:      "
#define MEM_PREFIX            "Memory:    "
#define RELOAD_PREFIX         "Reload:    "
#define PT_PREFIX             "PT:        "
#define INTERFACE_PREFIX      "Interface: "
#define REDQUEEN_PREFIX       "Redqueen:  "
#define DISASM_PREFIX         "Disasm:    "
#define PAGE_CACHE_PREFIX     "PageCache: "
#define INTERFACE_PREFIX      "Interface: "
#define NESTED_VM_PREFIX      "Nested:    "


#define DEBUG_VM_PREFIX       "Debug:     "

#define COLOR	"\033[1;35m"
#define ENDC	"\033[0m"


#ifdef NYX_DEBUG
/*
 * qemu_log() is the standard logging enabled with -D
 * qemu_log_mask() is activated with additional -t nyx option
 */
#define debug_printf(format, ...)               qemu_log_mask(LOG_NYX, QEMU_PT_PRINT_PREFIX "(%s#:%d)\t"format, __BASE_FILE__, __LINE__, ##__VA_ARGS__)
#define debug_fprintf(fd, format, ...)          qemu_log_mask(LOG_NYX, QEMU_PT_PRINT_PREFIX "(%s#:%d)\t"format, __BASE_FILE__, __LINE__, ##__VA_ARGS__)

#define QEMU_PT_PRINTF(PREFIX, format, ...)     qemu_log_mask(LOG_NYX, QEMU_PT_PRINT_PREFIX COLOR PREFIX format ENDC "\n", ##__VA_ARGS__)
#define QEMU_PT_PRINTF_DBG(PREFIX, format, ...) qemu_log_mask(LOG_NYX, QEMU_PT_PRINT_PREFIX PREFIX "(%s#:%d)\t"format, __BASE_FILE__, __LINE__, ##__VA_ARGS__)
#define QEMU_PT_PRINTF_DEBUG(format, ...)       qemu_log_mask(LOG_NYX, QEMU_PT_PRINT_PREFIX DEBUG_VM_PREFIX "(%s#:%d)\t"format, __BASE_FILE__, __LINE__, ##__VA_ARGS__)
#else
#define debug_printf(format, ...) 
#define debug_fprintf(fd, format, ...) 
#define QEMU_PT_PRINTF(PREFIX, format, ...)
#define QEMU_PT_PRINTF_DBG(PREFIX, format, ...)
#define QEMU_PT_PRINTF_DEBUG(format, ...)  
#endif


#ifdef ENABLE_BACKTRACES

void qemu_backtrace(void);
void init_crash_handler(void);
void hexdump_kafl(const void* data, size_t size);

#endif
