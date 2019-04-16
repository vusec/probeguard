#ifndef RDEF_COMMON_H
#define RDEF_COMMON_H

#include <assert.h>
#include <stdint.h>
#include "rdef_logger.h"
#include <libgen.h>

#define RDEF_E_OK     0
#define RDEF_E_FAIL   -1
#define RDEF_MAX_STR_SIZE	255

#define RDEF_BASENAME(D, S, N)	({		\
	char *copy;				\
	copy = strdup(S);			\
	char *bname = basename(copy);		\
	char *dotpos = strchr(bname, '.');	\
	if (NULL != dotpos) {			\
		*dotpos = '\0';			\
	}					\
	strncpy(D, bname, N);			\
	})

typedef struct
{
  char* filename;
  uint64_t base;
} rdef_prog_info_t;

#endif
