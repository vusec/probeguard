#include "rdefender.h"
#include "rdef_common.h"

enum rdef_analysis_status rdef_get_decision(const char *pt_dump_file, const char *program_name, rdef_decision *decision)
{
  // switch on everything for now
  // TODO: Improve later
  (*decision).bbs_to_instrument = (unsigned *) malloc(sizeof(unsigned) * rdf_switchboard_size);
  for (unsigned i=0; i < rdf_switchboard_size; i++)
  {
    (*decision).bbs_to_instrument[i] = 1;
  }
  (*decision).status = RDEF_ANALYSIS_SUCCESS;
  return RDEF_ANALYSIS_SUCCESS;
}
