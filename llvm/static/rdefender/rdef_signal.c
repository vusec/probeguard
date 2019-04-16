#include "rdef_common.h"
#include "rdef_net.h"
#include "rdef_react.h"
#include "rdefender.h"
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#define RDEF_SIGNAL_ANOMALY	SIGSEGV
#define RDEF_SIGNAL_CROP	0x80000BADC0DE
#define RDEF_SIGNAL_HUGE_ALLOC  0x80000B16A70C
#define RDEF_SIGNAL_INDUCED_FAULT       0x0F000BA2
#define RDEF_INDUCED_FAULT_RATE_INDEX	919

extern uint64_t rdf_switchboard[32000];
static char recv_buffer[RDEF_MAX_STR_SIZE];

int rdef_throttle_induced_faults()
{
  static uint64_t induced_fault_counter = 0;

  induced_fault_counter++;
  if (induced_fault_counter % RDEF_INDUCED_FAULT_RATE_INDEX == 0) {
  	rdef_print_info("crash behaviour: counter:%llu\n", induced_fault_counter);
	return 1;
  } else {
  	rdef_print_info("not crashing\n");
	return 0;
  }
}

void rdef_on_rwx_violation(siginfo_t *info)
{
  rdef_print_info("RWX violation detected\n"); 
}

void rdef_on_crop_violation(siginfo_t *info)
{
  rdef_print_info("CROP-like violation detected\n"); 
}

void rdef_on_alloc_violation(siginfo_t *info)
{
  rdef_print_info("Huge-allocation violation detected\n"); 
}

// Returns 0 upon failure.
uint64_t rdef_get_last_llvmid()
{
  // Talk to rdef-server to get the info from diagnoser
  char msg[16];
  sprintf(msg, "crashed %d ", getpid());
  if (RDEF_E_FAIL == rdef_send(msg))
  {
     rdef_print_error("Failed informing rdef-server about the crash.\n");
     return 0;
  }
  
  size_t recd = rdef_receive(recv_buffer, 10);
  if (0 >= recd)
  {
     rdef_print_error("Failed receiving response from rdef-server.\n");
     return 0;
  }
  recv_buffer[recd] = '\0'; 
  char* rest;
  uint64_t llvmid = strtoull(recv_buffer, &rest, 10);
  return llvmid;
}

void rdef_inform_parent(uint64_t llvmid)
{
  // update and notify parent by a dbt-cmdsvr ?
  char msg[10];
  sprintf(msg, "%lu\n", llvmid);
  if (RDEF_E_FAIL == rdef_send_to_parent(msg, strlen(msg)))
  {
     rdef_print_error("Failed informing parent. Exiting without enabling defenses.\n");
     return;
  }
  rdef_print_info("Informed parent to enable defense for function: %lu\n", llvmid);
  return;
}

/*
void rdef_signal_action(int signo, siginfo_t *info, void *context)
{
  rdef_print_info("rdef_signal_action: simply returning back\n");
  return;
}
*/


void rdef_signal_action(int signo, siginfo_t *info, void *context)
{
  rdef_print_info("Received signal: %d\n", signo);
  if (RDEF_SIGNAL_ANOMALY != signo)
	exit(1);

  assert(NULL != info && "siginfo_t received is NULL");

  uint64_t filter = (uint64_t)info->si_addr;

  // As of now, the following is just for logging sake.
  // It will be useful when we support selecting defense based on 
  // exactly the kind of violation that occurred. Currently, we enable all 
  // defenses that we support, for that function identified by llvmid.

  switch (filter) {
	case RDEF_SIGNAL_CROP:
		rdef_on_crop_violation(info);
		break;

	case RDEF_SIGNAL_HUGE_ALLOC:
		rdef_on_alloc_violation(info);
		break;

	case RDEF_SIGNAL_INDUCED_FAULT:
		if (0 == rdef_throttle_induced_faults()) {
			return; // ignore
		}
		break;

	default:
		rdef_on_rwx_violation(info);
		break;
  }

 /*
   Child
   1. Invoke the diagnoser to get the last LLVM ID 
	[ Talk to the RDEF server and receive ]
   2. Find out the function that the ID belongs to
	[ ? ]
   3. Inform parent about the function to run instrumented
	[ Use pipe[1] to write the rdef_switchboard[x] value and send a signal to parent ]	
   4. Die
  
   Parent:
   Just Die! There is nothing much we can do when parent dies
 */


  uint64_t llvmid = rdef_get_last_llvmid();	// function that crashed the program
  if (0 != llvmid) {
	rdf_switchboard[llvmid] = 1;
//	rdef_inform_parent(llvmid);
  	return;
  }

  //rdef_on_detect();
  exit(1);
} 


// Note: Child processes inherit signal handlers.
int rdef_register_detector()
{
  struct sigaction sa;
 
  memset(&sa, 0, sizeof(struct sigaction));
  sa.sa_sigaction = rdef_signal_action;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  
  if (0 > sigaction(RDEF_SIGNAL_ANOMALY, &sa, NULL)) {
    rdef_print_error("Failed to register signal action handler.\n");
    return RDEF_E_FAIL;
  }
  rdef_print_info("Registered RDEF signal handler.\n");
  return RDEF_E_OK;
}

#ifdef RDEF_HARDEN_ONE_FUNC
__attribute__((constructor))
int rdef_set_one_func_defense()
{
    char *str_func_id = getenv("FUNC");

    printf("Func to activate hardening for : %s\n", str_func_id);
    uint64_t func_id = strtol(str_func_id, NULL, 10);
    printf("Func to activate hardening for : %s(%llu)\n", str_func_id, func_id);
    assert(func_id <= rdf_switchboard_size);
    rdf_switchboard[func_id] = 1;
}
#endif
