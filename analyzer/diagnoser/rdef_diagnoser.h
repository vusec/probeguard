#ifndef RDEF_DIAG_H
#define RDEF_DIAG_H

#include "rdef_common.h"
#include "rdef_pt.h"
#include "rdef_dwarf.h"
#include "rdef_xed.h"

typedef struct
{
  pt_context_t pt_ctx;
  int dwarf_addr_map_loaded:1;
} rdef_diagnoser_t;

typedef struct
{
  uint64_t value;
  UT_hash_handle hh;
} rdef_set_element_t;

typedef struct
{
  rdef_set_element_t set[RDEF_MAX_HMAP_SIZE];
  uint64_t next_free;
  rdef_set_element_t *index;
} rdef_set_t;

int rdef_diagnoser_init(char *pt_dump_filename, char *sideband_filename, rdef_prog_info_t prog_files[], unsigned num_prog_files, rdef_diagnoser_t *diagnoser);
int rdef_get_unique_insn_addrs_from_dump(rdef_diagnoser_t *diagnoser, rdef_set_t **insn_addrs, uint64_t *num_insns);

// int rdef_walk_init(rdef_diagnoser_t *diagnoser);
// uint64_t rdef_walk_get_next_element(rdef_diagnoser_t *diagnoser);
// int rdef_walk_close(rdef_diagnoser_t *diagnoser);
#endif
