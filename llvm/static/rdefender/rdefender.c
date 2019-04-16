#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "rdef_common.h"
#include "rdefender.h"
#include "rdef_net.h"
#include "rdef_test.h"
#include "rdef_signal.h"
#include "rdef_react.h"

#define RDEF_MAX_SWITCHES       32000

pid_t rdf_pid;                        // To be initialized by the newly forked "eventually victim" process.
char rdf_program_name[RDEF_MAX_STR_SIZE] = "";
char rdf_ptdump_filename[RDEF_MAX_STR_SIZE] = "";
unsigned rdf_switchboard[RDEF_MAX_SWITCHES];                   // To be initialized by RDEF instrumentation pass
uint64_t rdf_switchboard_size = 1;        // To be initialized by RDEF instrumentation pass to the last-assigned-id.

// debug
unsigned rdf_something;

// logging
FILE *rdef_log_fptr = NULL;
char rdef_log_filename[RDEF_MAX_STR_SIZE] = "/tmp/rdef.log";

// Internal functions
int rdef_dump_pt(); // Interacting with pt recorder
int rdef_receive_diagnosis(rdef_decision *decision);  // Interacting with the diagnoser
void rdef_activate_defenses(const unsigned *switch_indices, size_t num_entries);

// ++ Target process initialization routine --
//int rdef_init(char **argv)
int rdef_init()
{
  rdf_pid = getpid();
#if 0
  rdef_print_info("prog-name: %15s\n", argv[0]);
  strncpy(rdf_program_name, argv[0], RDEF_MAX_STR_SIZE-11);
  sprintf(rdf_ptdump_filename, "%s_%d.pt", rdf_program_name, rdf_pid);
  rdef_print_info("prog-name stored: %s\n", rdf_program_name);
  }
#endif

  rdef_register_detector();

#if 0 
  // prepare for communication with PT Recorder
  if (RDEF_E_OK != rdef_net_init())
  {
    rdef_print_error("Process-specific initialization failed.\n");
    return RDEF_E_FAIL;
  }
#endif

  rdef_cmdsvr_init();
  rdef_print_info("Initialization done.\n");
  return RDEF_E_OK;
}

int rdef_init_child()
{
  // only child process need PT tracing
  // prepare for communication with PT Recorder
  if (RDEF_E_OK != rdef_net_init())
  {
    rdef_print_error("Process-specific initialization failed.\n");
    return RDEF_E_FAIL;
  }
  return RDEF_E_OK;
}

// ++ This is the entry point for the defender
// (Anomaly detecter shall call this function)-- 
int rdef_on_detect()
{
  rdef_decision decision;

  // 1. Dump PT trace for the victim process
  rdef_dump_pt(rdf_ptdump_filename);

  // 2. Invoke analyzer to gather relevant affected basic blocks, perform LLVM based analyses
  //    and decide what to do
  int r = rdef_receive_diagnosis(&decision);
  if (RDEF_E_OK != r)
  {
    rdef_print_error("analysis failure (%d)\n", decision.status);
    return RDEF_E_FAIL;
  }

  // 3. Act on decision.
  rdef_activate_defenses(decision.bbs_to_instrument, decision.num_entries);
  return RDEF_E_OK;
}

// Internal functions definitions.

int rdef_dump_pt(const char *filename)
{
  // send the filename to dump PT trace and receive ACK.
  int r;
  r = rdef_send(filename);
  if (RDEF_E_FAIL == r)
  {
    return RDEF_E_FAIL;
  }
  r = rdef_receive_ack();
  if (r > 0)
  {
    return RDEF_E_OK;
  }
  return RDEF_E_FAIL;
}

int rdef_receive_diagnosis(rdef_decision *decision)
{
  // Currently the diagnoser and the defender remain in the
  // same process - ie., within the target server process.
  // TODO: separate the diagnoser and perform a synchronous call
  // to the diagnoser to initiate analysis and receive the decision.
  enum rdef_analysis_status status;
  status = rdef_get_decision(rdf_ptdump_filename, rdf_program_name, decision);
  if (RDEF_ANALYSIS_SUCCESS == status)
  {
    return RDEF_E_OK;
  }
  rdef_print_error("Analysis failure: rdef_analysis_status: %d\n", status);
  return RDEF_E_FAIL;
}

void rdef_activate_defenses(const unsigned *switch_indices, size_t num_entries)
{
  // turn on all the switches. That's it.
  for (int i=0; i < num_entries; i++)
  {
    if (*(switch_indices+i) > rdf_switchboard_size)
    {
      rdef_print_warning("switchboard index out of bound: index: %d and size: %lu", switch_indices[i], rdf_switchboard_size);
      continue;
    }
    rdf_switchboard[*(switch_indices+i)] = 1;
  }
  // Just for now, for TRIAL_PURPOSE
  //rdf_use_instrumented = 1;
  return;
}
