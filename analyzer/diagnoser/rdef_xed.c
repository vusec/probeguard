/*
 * Copyright (c) 2013-2015, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Intel Corporation nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * MODIFICATION-DETAILS:
 *
 * Repurposed for retrieving instruction addresses from PT image
 * Author: Koustubha Bhat
 * Date : 30-May-2016
 * Vrije Universiteit, Amsterdam, The Netherlands.
 *
 * Original source: https://github.com/01org/processor-trace/blob/master/ptxed/src/ptxed.c
 */

#include "rdef_xed.h"

static xed_state_t g_xed;
static int g_xed_state_initialized = 0;

static xed_machine_mode_enum_t translate_mode(enum pt_exec_mode mode)
{
	switch (mode) {
	case ptem_unknown:
		return XED_MACHINE_MODE_INVALID;

	case ptem_16bit:
		return XED_MACHINE_MODE_LEGACY_16;

	case ptem_32bit:
		return XED_MACHINE_MODE_LEGACY_32;

	case ptem_64bit:
		return XED_MACHINE_MODE_LONG_64;
	}

	return XED_MACHINE_MODE_INVALID;
}

void rdef_xed_init(xed_machine_mode_enum_t mode)
{
  xed_tables_init();
  xed_state_zero(&g_xed);
  xed_state_set_machine_mode(&g_xed, mode);
  g_xed_state_initialized = 1;
}

void rdef_xed_print_insn(const struct pt_insn *insn, uint64_t offset)
{
  xed_state_t *xed = &g_xed;

  if (!g_xed_state_initialized)
  {
    rdef_print_error("%s : xed not initialized yet.\n", __func__);
    return;
  }

	if (!insn) {
		printf("[internal error]\n");
		return;
	}

	if (insn->resynced)
		printf("[overflow]\n");

	if (insn->enabled)
		printf("[enabled]\n");

	if (insn->resumed)
		printf("[resumed]\n");

	if (insn->speculative)
		printf("? ");

	printf("%016" PRIx64 "  ", offset);

	printf("%016" PRIx64, insn->ip);

		xed_machine_mode_enum_t mode;
		xed_decoded_inst_t inst;
		xed_error_enum_t errcode;

		mode = translate_mode(insn->mode);

		xed_state_set_machine_mode(xed, mode);
		xed_decoded_inst_zero_set_mode(&inst, xed);

		errcode = xed_decode(&inst, insn->raw, insn->size);
		switch (errcode) {
		case XED_ERROR_NONE: {
			xed_print_info_t pi;
			char buffer[256];
			xed_bool_t ok;

			xed_init_print_info(&pi);
			pi.p = &inst;
			pi.buf = buffer;
			pi.blen = sizeof(buffer);
			pi.runtime_address = insn->ip;

			pi.syntax = XED_SYNTAX_ATT;

			ok = xed_format_generic(&pi);
			if (!ok) {
				printf(" [xed print error]");
				break;
			}

			printf("  %s", buffer);
		}
			break;

		default:
			printf(" [xed decode error: (%u) %s]", errcode,
			       xed_error_enum_t2str(errcode));
			break;
		}

	printf("\n");

	if (insn->interrupted)
		printf("[interrupt]\n");

	if (insn->aborted)
		printf("[aborted]\n");

	if (insn->committed)
		printf("[committed]\n");

	if (insn->disabled)
		printf("[disabled]\n");

	if (insn->stopped)
		printf("[stopped]\n");

  return;
}
