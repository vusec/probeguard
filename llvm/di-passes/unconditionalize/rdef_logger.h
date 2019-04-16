#ifndef RDEF_LOGGER_H
#define RDEF_LOGGER_H

#include <stdio.h>

#ifdef NOPRINT

#define rdef_print_info(...) 		;
#define rdef_print_warning(...) 	;
#define rdef_print_error(...) 		;
#define rdef_print_debug(...)		;

#else
#define rdef_print_level(L, ...)  \
              printf("reactive_defense %s: ", L); printf(__VA_ARGS__);
#define rdef_print_info(...) \
              rdef_print_level("INFO", __VA_ARGS__);
#define rdef_print_warning(...) \
                            rdef_print_level("WARNING", __VA_ARGS__);
#define rdef_print_error(...) \
              rdef_print_level("ERROR", __VA_ARGS__);

#ifdef DEBUG
#define rdef_print_debug(...) \
              rdef_print_level("DEBUG", __VA_ARGS__);
#else
#define rdef_print_debug(...) \
	      ;
#endif
#endif
#endif
