#ifndef RDEF_DWARF_H
#define RDEF_DWARF_H

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <dwarf.h>
#include <libdwarf.h>
#include <common/ut/uthash.h>
#include "rdef_logger.h"

#define RDEF_E_OK     0
#define RDEF_E_FAIL   -1
#define RDEF_MAX_STR_SIZE       255
#define RDEF_MAX_HMAP_SIZE      32 * 1024 * 5
#define RDEF_BASENAME(D, S, N)  ({              \
        char *copy;                             \
        copy = strdup(S);                       \
        char *bname = basename(copy);           \
        char *dotpos = strchr(bname, '.');      \
        if (NULL != dotpos) {                   \
                *dotpos = '\0';                 \
        }                                       \
        strncpy(D, bname, N);                   \
        })

typedef struct
{
  uint64_t addr;
  uint64_t llvm_id;
  UT_hash_handle hh;
} map_element_t;

typedef struct
{
  map_element_t map[RDEF_MAX_HMAP_SIZE];
  uint64_t next_free;
  map_element_t *index;
} addr_llvm_id_map_t;

int rdef_dwf_load(const char *prog);
uint64_t rdef_dwf_get_assigned_id(uint64_t addr);

#endif
