
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "qemu/osdep.h"
#include "signal.h"

#include "nyx/debug.h"
#include "nyx/helpers.h"

#ifdef ENABLE_BACKTRACES
#define BT_BUF_SIZE 100

void qemu_backtrace(void)
{
    void *buffer[BT_BUF_SIZE];
    int   nptrs = 0;
    int   j;

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    nyx_printf("backtrace() returned %d addresses:\n", nptrs);


    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        nyx_error("backtrace_symbols failed!\n");
        return;
    }

    for (j = 0; j < nptrs; j++)
        nyx_printf("\t%s\n", strings[j]);

    free(strings);
}

static void sigsegfault_handler(int signo, siginfo_t *info, void *extra)
{
    nyx_printf("Crash detected (pid: %d / signal: %d)\n", getpid(), signo);
    qemu_backtrace();
#ifdef NYX_DEBUG
    nyx_printf("WAITING FOR GDB ATTACH... (PID: %d)\n", getpid());
    while (1) {
        sleep(1);
    }
#else
	nyx_abort("Exit after SIGSEGV. Check logs for details.");
#endif /* NYX_DEBUG */
}

static void sigabrt_handler(int signo, siginfo_t *info, void *extra)
{
    nyx_printf("Abort detected (pid: %d / signal: %d)\n", getpid(), signo);
    qemu_backtrace();
#ifdef NYX_DEBUG
    nyx_printf("WAITING FOR GDB ATTACH... (PID: %d)\n", getpid());
    while (1) {
        sleep(1);
    }
#else
	nyx_abort("Exit after SIGABRT. Check logs for details.");
#endif /* NYX_DEBUG */
}

static void sigint_handler(int signo, siginfo_t *info, void *extra)
{
    nyx_error("Bye! (pid: %d / signal: %d)\n", getpid(), signo);
    exit(0);
}

void init_crash_handler(void)
{
    struct sigaction action;
    action.sa_flags     = SA_SIGINFO;
    action.sa_sigaction = sigsegfault_handler;

    if (sigaction(SIGSEGV, &action, NULL) == -1) {
        nyx_abort("Failed to install SIGSEGV handler\n");
    }


    action.sa_sigaction = sigabrt_handler;

    if (sigaction(SIGABRT, &action, NULL) == -1) {
        nyx_abort("Failed to install SIGABRT handler\n");
    }

    /* don't install a SIGINT handler if the nyx block cow cache layer is disabled */
    if (!getenv("NYX_DISABLE_BLOCK_COW")) {
        action.sa_sigaction = sigint_handler;
        if (sigaction(SIGINT, &action, NULL) == -1) {
            nyx_abort("Failed to install SIGINT handler\n");
        }
    }
}

void hexdump_kafl(const void *data, size_t size)
{
    char   ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

#endif
