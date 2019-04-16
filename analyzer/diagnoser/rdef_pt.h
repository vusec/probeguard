#ifndef RDEF_PT_READER_H
#define RDEF_PT_READER_H

#ifdef FEATURE_ELF
# include "load_elf.h"
#endif /* defined(FEATURE_ELF) */

// #include "pt_cpu.h"

#include "intel-pt.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "rdef_common.h"
#include "rdef_sideband.h"

#define RDEF_TRACE_FORWARDS      0
#define RDEF_TRACE_BACKWARDS     1

/* A collection of options. [Hard-coded for our use]*/
struct ptxed_options {

	/* Print information about section loads and unloads. */
	uint32_t track_image:1;

	/* Print in AT&T format. */
	uint32_t att_format:1; // TODO: Move this option to rdef_pt_xed module

#ifdef FEATURE_ELF
  uint8_t elf_binary:1;
#endif
};

/* A collection of statistics. */
struct ptxed_stats {
	/* The number of instructions. */
	uint64_t insn;
};

typedef struct
{
  struct pt_insn_decoder *decoder;
  struct pt_image *image;
} pt_context_t;

int ptrdr_init(rdef_prog_info_t prog_files[], unsigned num_progs, char* ptdump_filename, char* sideband_filename, \
	       struct ptxed_options options, struct pt_insn_decoder **decoder, struct pt_image **image);
int ptrdr_sync(struct pt_insn_decoder *decoder, int *is_eos, int backwards, uint64_t offset);
int ptrdr_next_insn(struct pt_insn_decoder *decoder, struct pt_insn *insn, int *is_eos);
int ptrdr_next_insn_addr(struct pt_insn_decoder *decoder, uint64_t *next_addr, int *is_eos);
int ptrdr_get_n_insn_addrs(struct pt_insn_decoder *decoder, uint64_t *addr_start, uint64_t num_addrs_limit);
void ptrdr_close(struct pt_insn_decoder *decoder, struct pt_image *image);
int ptrdr_xedecode(const struct pt_insn *insn, FILE *fp);
int rdef_extract_base(char *arg, uint64_t *base, const char *prog_filename);
#endif
