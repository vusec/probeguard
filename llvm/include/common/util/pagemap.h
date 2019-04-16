#ifndef _UTIL_PAGEMAP_H
#define _UTIL_PAGEMAP_H

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "proc_maps.h"

#define UTIL_PAGEMMAP_DEFAULT_BUFF_SIZE    (PAGE_SIZE*10)

#define PME_PRESENT     (1Ull << 63)
#define PME_SOFT_DIRTY  (1Ull << 55)

#define CR_SOFTDIRTY   "4"

#define MAX(X, Y) (X > Y ? X : Y)
#define MIN(X, Y) (X < Y ? X : Y)

typedef unsigned long long u64_t;

typedef struct util_pagemap_s {
    u64_t *map;
    size_t buff_len;
    int fd;
    int cr_fd;
    pid_t pid;
} util_pagemap_t;

typedef int (*util_pagemap_walk_cb)(u64_t *entry, void *addr, void *cb_args);

static inline int util_pagemap_init(pid_t pid, util_pagemap_t *pm,
    void *map_buff, size_t map_buff_len)
{
    char buff[512];
    sprintf(buff, "/proc/%d/pagemap", pid);
    pm->fd = open(buff, O_RDONLY);
    if (pm->fd < 0) {
        return pm->fd;
    }
    sprintf(buff, "/proc/%d/clear_refs", pid);
    pm->cr_fd = open(buff, O_WRONLY);
    if (pm->cr_fd < 0) {
        close(pm->fd);
        return pm->cr_fd;
    }
    pm->pid = pid;
    if (!map_buff) {
        pm->map = (u64_t*) mmap(NULL, UTIL_PAGEMMAP_DEFAULT_BUFF_SIZE,
            PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
        assert(pm->map != MAP_FAILED);
        pm->buff_len = UTIL_PAGEMMAP_DEFAULT_BUFF_SIZE;
    }
    else {
        pm->map = map_buff;
        pm->buff_len = map_buff_len;
        assert(map_buff_len);
    }

    return 0;
}

static inline void util_pagemap_close(util_pagemap_t *pm)
{
    munmap(pm->map, pm->buff_len);
    close(pm->fd);
    close(pm->cr_fd);
    memset(pm, 0, sizeof(util_pagemap_t));
}

static inline int util_pagemap_get(util_pagemap_t *pm, void *addr, size_t len)
{
    int ret;
    size_t size = (len / PAGE_SIZE) * sizeof(u64_t);
    off_t offset = (unsigned long)addr / PAGE_SIZE * sizeof(u64_t);

    assert(size <= pm->buff_len);
    while(((ret = pread(pm->fd, pm->map, size, offset)) >=0 && ret != size)
        || (ret < 0 && errno == EINTR));
    return ret;
}

static inline u64_t* util_pagemap_entry(util_pagemap_t *pm, off_t index)
{
    return &pm->map[index];
}

static inline int util_pagemap_clear_refs(util_pagemap_t *pm, char *value)
{
    int ret;
    size_t size = 2;

    while (((ret = pwrite(pm->cr_fd, value, size, 0)) >=0 && ret != size)
        || (ret < 0 && errno == EINTR));
    return ret;
}

static inline int util_pagemap_walk(util_pagemap_t *pm, void *addr, size_t len,
    u64_t flags, util_pagemap_walk_cb cb, void *cb_args)
{
    size_t i, size, num_entries;
    int ret = 0;

    assert(len % PAGE_SIZE == 0);
    while (len > 0) {
        size = MIN(UTIL_PAGEMMAP_DEFAULT_BUFF_SIZE, len);
        ret = util_pagemap_get(pm, addr, size);
        if (ret < 0) {
            return ret;
        }
        num_entries = size/PAGE_SIZE;
        for (i=0;i<num_entries;i++) {
            u64_t *entry = util_pagemap_entry(pm, i);
            if (!flags || ((*entry) & flags)) {
                ret = cb(entry, addr, cb_args);
                if (ret < 0) {
                    return ret;
                }
            }
            addr = (char*)addr + PAGE_SIZE;
        }
        len -= size;
    }

    return ret;
}

static inline int util_pagemap_proc_walk(util_pagemap_t *pm,
    util_proc_maps_t *maps, u64_t flags, util_pagemap_walk_cb cb, void *cb_args)
{
    int i;
    int ret;

    for (i=0;i<maps->num_entries;i++) {
        unsigned long start = maps->entries[i].vm_start;
        unsigned long end = maps->entries[i].vm_end;
        ret = util_pagemap_walk(pm, (void*) start, end-start,
            flags, cb, cb_args);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

#endif /* _UTIL_PAGEMAP_H */

