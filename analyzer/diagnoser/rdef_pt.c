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

#include "rdef_pt.h"

// static void version(const char *name)
// {
// 	struct pt_version v = pt_library_version();
//
// 	printf("%s-%d.%d.%d%s / libipt-%" PRIu8 ".%" PRIu8 ".%" PRIu32 "%s\n",
// 	       name, PT_VERSION_MAJOR, PT_VERSION_MINOR, PT_VERSION_BUILD,
// 	       PT_VERSION_EXT, v.major, v.minor, v.build, v.ext);
// }

int rdef_extract_base(char *arg, uint64_t *base, const char *prog_filename)
{
	char *sep, *rest;

	sep = strstr(arg, ":");
	if (sep) {
		errno = 0;
		*base = strtoull(sep+1, &rest, 0);
		if (errno || *rest) {
			fprintf(stderr, "%s: bad argument: %s.\n", prog_filename, arg);
			return -1;
		}

		*sep = 0;
		return 1;
	}

	return 0;
}

static int parse_range(char *arg, uint64_t *begin, uint64_t *end)
{
	char *rest;

	if (!arg)
		return 0;

	errno = 0;
	*begin = strtoull(arg, &rest, 0);
	if (errno)
		return -1;

	if (!*rest)
		return 0;

	if (*rest != '-')
		return -1;

	*end = strtoull(rest+1, &rest, 0);
	if (errno || *rest)
		return -1;

	return 0;
}

static int load_file(uint8_t **buffer, size_t *size, char *arg,
		     const char *prog_filename)
{
	uint64_t begin_arg, end_arg;
	uint8_t *content;
	size_t read;
	FILE *file;
	long fsize, begin, end;
	int errcode;
	char *range;

	if (!buffer || !size || !arg || !prog_filename) {
		fprintf(stderr, "%s: internal error.\n", prog_filename ? prog_filename : "");
		return -1;
	}

	range = strstr(arg, ":");
	if (range) {
		range += 1;
		range[-1] = 0;
	}

	errno = 0;
	file = fopen(arg, "rb");
	if (!file) {
		fprintf(stderr, "%s: failed to open %s: %d.\n",
			prog_filename, arg, errno);
		return -1;
	}

	errcode = fseek(file, 0, SEEK_END);
	if (errcode) {
		fprintf(stderr, "%s: failed to determine size of %s: %d[%s].\n",
			prog_filename, arg, errcode, pt_errstr(pt_errcode(errcode)));
		goto err_file;
	}

	fsize = ftell(file);
	if (fsize < 0) {
		fprintf(stderr, "%s: failed to determine size of %s: %d.\n",
			prog_filename, arg, errno);
		goto err_file;
	}

	begin_arg = 0ull;
	end_arg = (uint64_t) fsize;
	errcode = parse_range(range, &begin_arg, &end_arg);
	if (errcode < 0) {
		fprintf(stderr, "%s: bad range: %s: %d[%s].\n", prog_filename, range, errcode, pt_errstr(pt_errcode(errcode)));
		goto err_file;
	}

	begin = (long) begin_arg;
	end = (long) end_arg;
	if ((uint64_t) begin != begin_arg || (uint64_t) end != end_arg) {
		fprintf(stderr, "%s: invalid offset/range argument.\n", prog_filename);
		goto err_file;
	}

	if (fsize <= begin) {
		fprintf(stderr, "%s: offset 0x%lx outside of %s.\n",
			prog_filename, begin, arg);
		goto err_file;
	}

	if (fsize < end) {
		fprintf(stderr, "%s: range 0x%lx outside of %s.\n",
			prog_filename, end, arg);
		goto err_file;
	}

	if (end <= begin) {
		fprintf(stderr, "%s: bad range.\n", prog_filename);
		goto err_file;
	}

	fsize = end - begin;

	content = malloc(fsize);
	if (!content) {
		fprintf(stderr, "%s: failed to allocated memory %s.\n",
			prog_filename, arg);
		goto err_file;
	}

	errcode = fseek(file, begin, SEEK_SET);
	if (errcode) {
		fprintf(stderr, "%s: failed to load %s: %d[%s].\n",
			prog_filename, arg, errcode, pt_errstr(pt_errcode(errcode)));
		goto err_content;
	}

	read = fread(content, fsize, 1, file);
	if (read != 1) {
		fprintf(stderr, "%s: failed to load %s: %d.\n",
			prog_filename, arg, errno);
		goto err_content;
	}

	fclose(file);

	*buffer = content;
	*size = fsize;

	return 0;

err_content:
	free(content);

err_file:
	fclose(file);
	return -1;
}

static int load_pt(struct pt_config *config, char *arg, const char *prog_filename)
{
	uint8_t *buffer;
	size_t size;
	int errcode;

	errcode = load_file(&buffer, &size, arg, prog_filename);
	if (errcode < 0)
		return errcode;

	config->begin = buffer;
	config->end = buffer + size;

	return 0;
}

static int load_raw(struct pt_image *image, char* binary_filename, uint64_t base, const char *prog_filename)
{
	int errcode;
	errcode = pt_image_add_file(image, binary_filename, 0, UINT64_MAX, NULL, base);
	if (errcode < 0) {
		fprintf(stderr, "%s: failed to add %s at 0x%" PRIx64 ": %s.\n",
			prog_filename, binary_filename, base, pt_errstr(pt_errcode(errcode)));
		return 1;
	}

	return 0;
}

static void diagnose(const char *errtype, struct pt_insn_decoder *decoder,
		     const struct pt_insn *insn, int errcode)
{
	int err;
	uint64_t pos;

	err = pt_insn_get_offset(decoder, &pos);
	if (err < 0) {
		printf("could not determine offset: %s\n",
		       pt_errstr(pt_errcode(err)));
		printf("[?, %" PRIx64 ": %s: %s]\n", insn->ip, errtype,
		       pt_errstr(pt_errcode(errcode)));
	} else
		printf("[%" PRIx64 ", %" PRIx64 ": %s: %s]\n", pos,
		       insn->ip, errtype, pt_errstr(pt_errcode(errcode)));
}

int ptrdr_init(rdef_prog_info_t prog_files[], unsigned num_prog_files, char* ptdump_filename, char* sideband_filename, struct ptxed_options options, struct pt_insn_decoder **decoder, struct pt_image **image)
{
  struct pt_config config;
  int errcode, i;

  if (*decoder)
  {
    rdef_print_info("%s : decoder is NOT NULL. Possibly been already initialized.\n", __func__);
    return RDEF_E_OK;
  }
  if (0 == num_prog_files)
  {
    rdef_print_error("%s : target program is not specified.\n", __func__);
    return RDEF_E_FAIL;
  }

  // TODO: Do we like to track any stats?

  /* Step 1. Init config structure */
  rdef_print_info("Initializing pt-config.\n");
  pt_config_init(&config);
  errcode = pt_cpu_errata(&config.errata, &config.cpu);
  if (errcode < 0)
    goto err;

  // errcode = pt_cpu_read(&config.cpu);
  // if (errcode < 0)
  // {
  //   rdef_print_error("%s: error reading cpu: %s.\n",prog_filename, pt_errstr(pt_errcode(errcode)));
  //   return 1;
  // }

  /* Step 2. Load pt dump onto the config structure */
  rdef_print_info("Loading pt-dump file.\n");
  errcode = load_pt(&config, ptdump_filename, prog_files[0].filename);
  if (errcode < 0)
    goto err;

  /* Step 3. Load target binary image onto pt_image */
  rdef_print_info("Loading target binary image.\n");
  *image = pt_image_alloc(NULL);
  if (!image)
  {
		rdef_print_error("%s: failed to allocate image.\n", prog_files[0].filename);
		return RDEF_E_FAIL;
  }

    // errcode = rdef_extract_base(arg, &base, prog_filename);
    // if (errcode < 0)
    //   goto err;
    for (unsigned i=0; i < num_prog_files; i++)
    {
#ifdef FEATURE_ELF
  	if (options.elf_binary)
	{
    	   errcode = load_elf(*image, prog_files[i].filename, prog_files[i].base, prog_files[i].filename, options.track_image);
    	   if (errcode < 0)
     	      goto err;
 	}
  	else
#endif
  	{
    	   errcode = load_raw(*image, prog_files[i].filename, prog_files[i].base, prog_files[0].filename);
	    if (errcode < 0)
     		 goto err;
  	}
    }
	
  /* Step 4. Read sideband information */
  if (NULL != sideband_filename)
  {
     rdef_print_info("Loading sideband information.\n");
     load_sideband(sideband_filename, *image, &config);
  }

  /* Step 5. Initialize decoder */
  rdef_print_info("Initializing the decoder.\n");
  *decoder = pt_insn_alloc_decoder(&config);
  if (!decoder)
  {
    rdef_print_error("%s: failed to create decoder.\n", prog_files[0].filename);
    goto err;
  }

  /* Step 6. Associate the decoder with the pt image */
  rdef_print_info("Associating the decoder with the target image.\n");
  errcode = pt_insn_set_image(*decoder, *image);
  if (errcode < 0)
  {
	rdef_print_error("%s: failed to set image.\n", prog_files[0].filename);
	goto err;
  }

  return RDEF_E_OK;

err:
  rdef_print_error("%s: Failure occured. %d[%s]\n", prog_files[0].filename, errcode, pt_errstr(pt_errcode(errcode)));
  ptrdr_close(*decoder, *image);
  return RDEF_E_FAIL;
}

void ptrdr_close(struct pt_insn_decoder *decoder, struct pt_image *image)
{
  if (!decoder)
    pt_insn_free_decoder(decoder);
  if (!image)
    pt_image_free(image);
  return;
}

int ptrdr_sync(struct pt_insn_decoder *decoder, int *is_eos, int backwards, uint64_t offset)
{
  if (!decoder || !is_eos)
  {
    rdef_print_error("%s : decoder not initialized.\n", __func__);
  }

  static uint64_t sync = 0ull;
  struct pt_insn insn;
  int errcode;
  *is_eos = 0;

  /* Initialize the IP - we use it for error reporting. */
  insn.ip = 0ull;
  if (backwards)
  {
    errcode = pt_insn_sync_backward(decoder);
  }
  else
  {
    errcode = pt_insn_sync_forward(decoder);
  }
  if (errcode < 0)
  {
    static uint64_t new_sync;

    if (errcode == -pte_eos)
    {
      rdef_print_info("%s : reached pt end-of-stream.\n", __func__);
			*is_eos = 1;
      return RDEF_E_OK;
    }
    diagnose("sync error", decoder, &insn, errcode);

    /* Let's see if we made any progress.  If we haven't,
     * we likely never will.  Bail out.
     *
     * We intentionally report the error twice to indicate
     * that we tried to re-sync.  Maybe it even changed.
     */
    errcode = pt_insn_get_offset(decoder, &new_sync);
    //if (errcode < 0 || (new_sync <= sync))
    if ( errcode < 0 || ((0ull != sync) && (new_sync >= sync)))
      return RDEF_E_FAIL;

    sync = new_sync;
  }
  if(offset)
  {
    errcode = pt_insn_sync_set(decoder, offset);
    if (errcode < 0)
    {
      rdef_print_warning("pt_insn_sync_set failed. offset : %lu\n", offset);
      return RDEF_E_FAIL;
    }
  }
  return RDEF_E_OK;
}

int ptrdr_next_insn(struct pt_insn_decoder *decoder, struct pt_insn *insn, int *is_eos)
{
  if (!insn || !is_eos)
  {
    rdef_print_error("%s : Argument error.\n", __func__);
    return RDEF_E_FAIL;
  }
  insn->ip = 0ull;

	uint64_t offset;
	int errcode;

  errcode = pt_insn_get_offset(decoder, &offset);
  if (errcode < 0)
  {
    rdef_print_error("%s : Could not get decoder's offset. (%s)\n", __func__, pt_errstr(-errcode));
    return RDEF_E_FAIL;
  }
  //rdef_print_info("%s : decoder's offset: %lx\n", __func__, offset);

  errcode = pt_insn_next(decoder, insn, sizeof(*insn));
  if (errcode < 0)
  {
			if (insn->iclass != ptic_error)
			{
				/* Even in case of errors, we may have succeeded
				 * in decoding the current instruction.
				 */
				 rdef_print_info("%s : errcode is %d (%s), but iclass is not ptic_error.\n", __func__, errcode, pt_errstr(-errcode));
			}
			else
			{
			    rdef_print_error("%s : Could not get next insn. addr: %lx (%s)\n", __func__, insn->ip, pt_errstr(-errcode));
			    return RDEF_E_FAIL;
			}
  }
  return RDEF_E_OK;
}

int ptrdr_next_insn_addr(struct pt_insn_decoder *decoder, uint64_t *next_addr, int *is_eos)
{
  struct pt_insn insn;
  int res;
	if (!decoder || !next_addr || !is_eos)
	{
		rdef_print_error("%s : Argument error.\n", __func__);
		return RDEF_E_FAIL;
	}

  res = ptrdr_next_insn(decoder, &insn, is_eos);
  if (RDEF_E_OK != res)
  {
    return RDEF_E_FAIL;
  }

  *next_addr = insn.ip;
  return RDEF_E_OK;
}
