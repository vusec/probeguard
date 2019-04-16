/****************************
* Primitives for testing
****************************/
#include <signal.h>
#include "rdef_common.h"
#include "rdef_test.h"

#define RDEF_SIGNAL	SIGCHLD

void rdef_test_crash()
{
  volatile char *p = 0;
  rdef_print_info("Crashing...\n");
  *p = '\0';
  return;
}

void rdef_test_init_signal()
{
  struct sigaction sa;
  sa.sa_handler = rdef_test_signal_handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(RDEF_SIGNAL, &sa, NULL) == -1)
  {
	rdef_print_error("Failed setting our test signal handler for %d\n", RDEF_SIGNAL);
  }
  rdef_print_info("Set %d signal handler.\n", RDEF_SIGNAL);
  return;
}

void rdef_test_signal_handler(int signo)
{
  // Handle the signal(s) we are interested in.
  rdef_print_info("in rdef test signal handler.\n");
  if (RDEF_SIGNAL == signo)
  {
    rdef_print_info("Caught SIGUSR1 signal. Crashing for testing purpose.\n");
    rdef_test_crash();
  }
  return;
}
