#ifndef RDEF_XED_H
#define RDEF_XED_H

#include "intel-pt.h"
#include <inttypes.h>
#include <xed-state.h>
#include <xed-init.h>
#include <xed-error-enum.h>
#include <xed-decode.h>
#include <xed-decoded-inst-api.h>
#include <xed-machine-mode-enum.h>

#include "rdef_common.h"

void rdef_xed_init();
void rdef_xed_print_insn(const struct pt_insn *insn, uint64_t offset);

#endif
