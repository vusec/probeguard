/*
 * Copyright (c) 2015, Intel Corporation
 * Author: Andi Kleen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include <intel-pt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <cpuid.h>
#include "rdef_logger.h"
#include "rdef_sideband.h"
#include "rdef_sideband_symtab.h"
#include "rdef_sideband_elf.h"

double tsc_freq;


/* Sideband format:
meta family num
meta model num
meta stepping num
meta mtc_freq num-1
meta num_freq num
meta tsc_ratio eax ebx
timestamp pid cr3 load-address off-in-file path-to-binary[:codebin]
 */
void load_sideband(char *fn, struct pt_image *image, struct pt_config *config)
{
	FILE *f = fopen(fn, "r");
	if (!f) {
		rdef_print_error("Cannot open %s: %s\n", fn, strerror(errno));
		exit(1);
	}
	char *line = NULL;
	size_t linelen = 0;
	int lineno = 1;
	for (;getline(&line, &linelen, f) > 0; lineno++) {
		uint64_t cr3, addr, off;
		unsigned pid;
		double ts;
		int n;

		if (!strncmp(line, "meta", 4)) {
			if (sscanf(line, "meta tsc_ratio %u %u",
					&config->cpuid_0x15_eax,
					&config->cpuid_0x15_ebx) == 2) {
				/* ok */
			} else if (sscanf(line, "meta family %hu",
					&config->cpu.family) == 1) {
				config->cpu.vendor = pcv_intel;
			} else if (sscanf(line, "meta model %hhu",
					&config->cpu.model) == 1) {
				/* ok */
			} else if (sscanf(line, "meta stepping %hhu",
					&config->cpu.stepping) == 1) {
			} else if (sscanf(line, "meta mtc_freq %hhu",
					&config->mtc_freq) == 1) {
				if (config->mtc_freq)
					config->mtc_freq--;
			} else if (sscanf(line, "meta nom_freq %hhu",
					&config->nom_freq) == 1) {
				tsc_freq = config->nom_freq / 10.0;
			} else {
				rdef_print_error("%s:%d: Unknown meta statement\n", fn, lineno);
			}
			continue;
		}

		if (sscanf(line, "%lf %u %lx %lx %lx %n", &ts, &pid, &cr3, &addr, &off, &n) != 5) {
			rdef_print_error("%s:%d: Parse error\n", fn, lineno);
			continue;
		}
		if (ts == 0 && !seen_cr3(cr3))
			continue;
		while (isspace(line[n]))
			n++;
		/* timestamp ignored for now. could later be used to distinguish
		   reused CR3s or reused address space. */
		/* pid ignored for now. should use in decoding. */
		char *p = strchr(line + n, '\n');
		if (p) {
			*p = 0;
			while (--p >= line + n && isspace(*p))
				*p = 0;
		}
		if (off != 0)
			rdef_print_error("FIXME: mmap %s has non zero offset %lx\n", fn, off);
		if (read_elf(line + n, image, addr, cr3)) {
			rdef_print_error("Cannot read %s: %s\n", line + n, strerror(errno));
		}
	}
	free(line);
	fclose(f);
}
