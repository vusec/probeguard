#ifndef RDEF_COMMON_H
#define RDEF_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define RDEF_E_OK      0
#define RDEF_E_FAIL   -1

#ifdef RDEF_LOG_TO_FILE
#define rdef_print_level(L, ...)  \
	      if (NULL != rdef_log_fptr) {					\
	              fprintf(rdef_log_fptr, "reactive_defense %s: ", L); 	\
		      fprintf(rdef_log_fptr, __VA_ARGS__);			\
		      fflush(rdef_log_fptr);					\
	      }
#else 
#define rdef_print_level(L, ...)  \
              printf("reactive_defense %s: ", L); printf(__VA_ARGS__); 
#endif

#define rdef_print_info(...) \
              rdef_print_level("INFO", __VA_ARGS__);
#define rdef_print_warning(...) \
                            rdef_print_level("WARNING", __VA_ARGS__);
#define rdef_print_error(...) \
              rdef_print_level("ERROR", __VA_ARGS__);
#define rdef_print_debug(...) \
	      rdef_print_level("DEBUG", __VA_ARGS__);

#define RDEF_MAX_STR_SIZE       250

extern pid_t rdf_pid;
extern uint64_t rdf_switchboard_size;
extern FILE *rdef_log_fptr;
extern char rdef_log_filename[RDEF_MAX_STR_SIZE];

#endif
