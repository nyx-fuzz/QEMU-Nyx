#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "nyx/debug.h"
#include "signal.h"

#ifdef ENABLE_BACKTRACES
#define BT_BUF_SIZE 100

void qemu_backtrace(void){
  void *buffer[BT_BUF_SIZE];
  int nptrs = 0;
  int j;

  nptrs = backtrace(buffer, BT_BUF_SIZE);
  fprintf(stderr, "backtrace() returned %d addresses\n", nptrs);


  char **strings = backtrace_symbols(buffer, nptrs);
  if (strings == NULL) {
      //perror("backtrace_symbols");
      fprintf(stderr, "backtrace_symbols failed!\n");
      return;
      //exit(EXIT_FAILURE);
  }

  for (j = 0; j < nptrs; j++)
      fprintf(stderr, "%s\n", strings[j]);

  free(strings);
}

static void sigsegfault_handler(int signo, siginfo_t *info, void *extra) {
  fprintf(stderr, "[qemu-nyx] crash detected (pid: %d / signal: %d)\n", getpid(), signo);
  qemu_backtrace();
  fprintf(stderr, "WAITING FOR GDB ATTACH (PID: %d...\n", getpid());
  while(1){
    sleep(1);
  }
}

static void sigabrt_handler(int signo, siginfo_t *info, void *extra) {
  fprintf(stderr, "[qemu-nyx] crash detected (pid: %d / signal: %d)\n", getpid(), signo);
  qemu_backtrace();
  fprintf(stderr, "WAITING FOR GDB ATTACH (PID: %d...\n", getpid());
  while(1){
    sleep(1);
  }
}

static void sigint_handler(int signo, siginfo_t *info, void *extra) {
  fprintf(stderr, "[qemu-nyx] bye! (pid: %d / signal: %d)\n", getpid(), signo);
  exit(0);
}

/*
static void aexit_handler(void) {
  fprintf(stderr, "ATTEMPT TO CALL EXIT (PID: %d)\n", getpid());
  qemu_backtrace();
  fprintf(stderr, "WAITING FOR GDB ATTACH (PID: %d...\n", getpid());
  while(1){
    sleep(1);
  }
}
*/

void init_crash_handler(void){

  //qemu_backtrace();

    struct sigaction action;
    action.sa_flags = SA_SIGINFO;
    action.sa_sigaction = sigsegfault_handler;

    if (sigaction(SIGSEGV, &action, NULL) == -1) {
        fprintf(stderr, "SIGSEGV: sigaction failed");
        _exit(1);
    }

  
  
    action.sa_sigaction = sigabrt_handler;

    if (sigaction(SIGABRT, &action, NULL) == -1) {
        fprintf(stderr, "SIGABRT: sigaction failed");
        _exit(1);
    }

  /* don't install a SIGINT handler if the nyx block cow cache layer is disabled */
	if(!getenv("NYX_DISABLE_BLOCK_COW")){
    action.sa_sigaction = sigint_handler;
    if (sigaction(SIGINT, &action, NULL) == -1) {
        fprintf(stderr, "SIGINT: sigaction failed");
        _exit(1);
    }
  }
  //atexit(aexit_handler);

  /* test */
   //int i = 0;
    //((char*)i)[3] = 0;

}

void hexdump_kafl(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

#endif
