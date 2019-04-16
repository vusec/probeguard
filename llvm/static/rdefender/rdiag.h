#ifndef RDIAG_H
#define RDIAG_H

#include <stdlib.h>
#include <sys/types.h>

enum rdef_analysis_status
{
  RDEF_ANALYSIS_SUCCESS,
  RDEF_ANALYSIS_FAILURE,
  RDEF_ANALYSIS_INVALID_PTDUMP,
  RDEF_ANALYSIS_IMPROPER_BINARY,
};

typedef struct
{
  enum rdef_analysis_status	status;
  size_t    num_entries;
  unsigned	*bbs_to_instrument;
} rdef_decision;

enum rdef_analysis_status rdef_get_decision(const char *pt_dump_file, const char *program_name, rdef_decision *decision);
#endif
