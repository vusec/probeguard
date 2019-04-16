#ifndef _UTIL_OUTPUT_H
#define _UTIL_OUTPUT_H

#include "util_def.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>

#include "safeio.h"
#include "env.h"

typedef int util_output_level_t;

typedef struct util_output_conf_s {
    FILE *fp;
    char* dir;
    char* file;
    util_output_level_t level;
    int fsync;
    int id;
    int id2;
} util_output_conf_t;

#define _UTIL_OUTPUT_LEVEL_MAX       50
#define _UTIL_OUTPUT_LEVEL_NONE      0
#define _UTIL_OUTPUT_LEVEL_BASIC     1

#define _UTIL_OUTPUT_DEFAULT_FILE    "app.out"
#define _UTIL_OUTPUT_DEFAULT_DIR     "/tmp"
#define _UTIL_OUTPUT_DEFAULT_LEVEL   _UTIL_OUTPUT_LEVEL_MAX
#define _UTIL_OUTPUT_DEFAULT_FSYNC   0
#define _UTIL_OUTPUT_NAME_TO_FILE(N) (N ".out")

static inline void util_output_printf_force(util_output_conf_t *conf,
    const char* fmt, ...) {
    va_list args;
    va_start(args,fmt);
    if (!conf->fp) {
        conf->fp = stderr;
    }
    vfprintf(conf->fp, fmt,args);
    va_end(args);
    if (conf->fsync && conf->fp) {
        fdatasync(fileno(conf->fp));
    }
}

#define util_output_printf_level(L, C, ...) do { \
    if (L <= (C)->level) { \
        util_output_printf_force(C, __VA_ARGS__); \
    } \
} while(0)

#define util_output_printf(...) \
    util_output_printf_level(_UTIL_OUTPUT_LEVEL_BASIC, __VA_ARGS__)

static inline void util_output_from_env(util_output_conf_t *conf) {
    /* Set defaults. */
    if (!conf->dir) {
        conf->dir = _UTIL_OUTPUT_DEFAULT_DIR;
    }
    if (!conf->file) {
        conf->file = _UTIL_OUTPUT_DEFAULT_FILE;
    }
    if (!conf->level) {
        conf->level = _UTIL_OUTPUT_DEFAULT_LEVEL;
    }
    if (!conf->fsync) {
        conf->fsync = _UTIL_OUTPUT_DEFAULT_FSYNC;
    }
    /* Override defaults from the environment. */
    conf->dir = util_env_parse_str("LOGDIR", conf->dir);
    conf->file = util_env_parse_str("LOGFILE", conf->file);
    conf->level = util_env_parse_int("LOGLEVEL", conf->level);
    conf->fsync = util_env_parse_int("LOGFSYNC", conf->fsync);
}

static inline void util_output_init(util_output_conf_t *conf) {
    char buff[512];

    if (conf->level == _UTIL_OUTPUT_LEVEL_NONE) {
        return;
    }
    if (!conf->fp && conf->dir) {
        if (conf->id2 > 0) {
            sprintf(buff, "%s/%s.%d.%d", conf->dir, conf->file, conf->id, conf->id2);
        }
        else {
            sprintf(buff, "%s/%s.%d", conf->dir, conf->file, conf->id);
        }
        conf->fp = fdopen(util_safeio_open(buff, O_CREAT | O_WRONLY | O_CLOEXEC, 0644), "w");
        if (!conf->fp) {
            fprintf(stderr, "WARNING: unable to open output file %s, resorting to stderr...\n", buff);
        }
    }
    if(!conf->fp) {
        int fd = dup(STDOUT_FILENO);
        if(fd < 0){
            fprintf(stderr, "ERROR: stdout duplication result: %d\n", fd);
            exit(1);
        }
        conf->fp = fdopen(fd, "w");
    }
    setbuf(conf->fp, NULL);
}

static inline void util_output_close_child(util_output_conf_t *conf) {
    if (conf->level == _UTIL_OUTPUT_LEVEL_NONE) {
        return;
    }
    if (conf->fp) {
        fclose(conf->fp);
        conf->fp = NULL;
    }
}

static inline void util_output_close(util_output_conf_t *conf) {
    util_output_close_child(conf);
}

#endif /* _UTIL_OUTPUT_H */
