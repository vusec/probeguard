#ifndef _UTIL_PROC_MAPS_H
#define _UTIL_PROC_MAPS_H

#include "util_def.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

#include <assert.h>

#include "bufread.h"

extern char *__progname;
extern char *__progname_full;

extern char __data_start[];
extern int main(int argc, char** argv);

extern __off64_t lseek64(int fd, __off64_t offset, int whence);

struct util_proc_maps_s;

typedef struct util_proc_maps_entry_s {
    unsigned long vm_start;
    unsigned long vm_end;
    char r, w, x, s;
    unsigned long long pgoff;
    int major, minor;
    unsigned long ino;
    char name[128];
    struct util_proc_maps_s *owner;
    char *buff;
} util_proc_maps_entry_t;

typedef struct util_proc_maps_s {
    pid_t pid;
    int num_entries;
    util_proc_maps_entry_t *entries;
} util_proc_maps_t;

typedef struct util_proc_maps_info_s {
    util_proc_maps_entry_t vm;
    util_proc_maps_entry_t prog;
    util_proc_maps_entry_t mmap;
    util_proc_maps_entry_t libs;
    util_proc_maps_entry_t *prog_text;
    util_proc_maps_entry_t *prog_ro;
    util_proc_maps_entry_t *prog_data;
    util_proc_maps_entry_t *heap;
    util_proc_maps_entry_t *stack;
    util_proc_maps_entry_t *vdso;
    util_proc_maps_entry_t *vsyscall;
    util_proc_maps_t maps;
    util_proc_maps_entry_t maps_entries[32];
} util_proc_maps_info_t;

typedef enum util_proc_maps_diff_flags_e {
    UTIL_PROC_MAPS_DIFF_ALLOW_NO_ENTRY,
    UTIL_PROC_MAPS_DIFF_ALLOW_NAME_DIFF,
    UTIL_PROC_MAPS_DIFF_ALLOW_PROT_DIFF,
    UTIL_PROC_MAPS_DIFF_ALLOW_SHARED_DIFF,
    UTIL_PROC_MAPS_DIFF_ALLOW_RANGE_DIFF,
    UTIL_PROC_MAPS_DIFF_ALLOW_RANGE_MISMATCH,
    UTIL_PROC_MAPS_DIFF_ALLOW_DATA_DIFF,
    __NUM_UTIL_PROC_MAPS_DIFF_FLAGS
} util_proc_maps_diff_flags_t;

typedef int (*util_proc_maps_parse_cb_t)(util_proc_maps_entry_t *entry,
    void *cb_args);

typedef int (*util_proc_maps_diff_cb_t)(util_proc_maps_entry_t *e1,
    util_proc_maps_entry_t *e2, int diffresult, void *cb_args);

typedef enum util_proc_maps_parse_ret_e {
    UTIL_PROC_MAPS_RET_SAVE,
    UTIL_PROC_MAPS_RET_SAVE_AND_STOP,
    UTIL_PROC_MAPS_RET_CONTINUE,
    UTIL_PROC_MAPS_RET_STOP,
    UTIL_PROC_MAPS_RET_ERR,
    __NUM_UTIL_PROC_MAPS_RETS
} util_proc_maps_parse_ret_t;

void *__heap_addr __attribute__((weak));

#define DIFF_FLAG(F) (1 << UTIL_PROC_MAPS_DIFF_ ## F)

#define MAX(X, Y) (X > Y ? X : Y)
#define MIN(X, Y) (X < Y ? X : Y)

#define __ANON            ""
#define __HEAP            "[heap]"
#define __VDSO            "[vdso]"
#define __VSYSCALL        "[vsyscall]"
#define __PROGNAME        __progname
#define __PROGNAME_FULL   __progname_full

#define UTIL_PROC_MAPS_PROG_TEXT_ADDR  ((unsigned long) (&main))
#define UTIL_PROC_MAPS_PROG_RO_ADDR \
    ((UTIL_PROC_MAPS_PROG_DATA_ADDR/PAGE_SIZE)*PAGE_SIZE-1)
#define UTIL_PROC_MAPS_PROG_DATA_ADDR  ((unsigned long) (&__data_start))
#define UTIL_PROC_MAPS_HEAP_ADDR       (__heap_addr ? __heap_addr : (__heap_addr=malloc(1)))
#define UTIL_PROC_MAPS_TLS_ADDR        ((unsigned long) (&errno))

#define UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, A) \
    (((unsigned long)(A)) >= (E)->vm_start \
    && ((unsigned long)(A)) < (E)->vm_end)
#define UTIL_PROC_MAPS_ENTRY_OVERLAPS(E, E2) \
    (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, (E2)->vm_start) || \
    UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, (E2)->vm_end-1) || \
    UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E2, (E)->vm_start) || \
    UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E2, (E)->vm_end-1))
#define UTIL_PROC_MAPS_ENTRY_RANGE_EQUALS(E, E2) \
    ((E)->vm_start == (E2)->vm_start && (E)->vm_end == (E2)->vm_end)
#define UTIL_PROC_MAPS_ENTRY_PROT_EQUALS(E, E2) \
    ((E)->r == (E2)->r && (E)->w == (E2)->w && (E)->x == (E2)->x)
#define UTIL_PROC_MAPS_ENTRY_SHARED_EQUALS(E, E2) \
    ((E)->s == (E2)->s)
#define UTIL_PROC_MAPS_ENTRY_NAME_EQUALS(E, E2) \
    (!strcmp((E)->name, (E2)->name))

#define UTIL_PROC_MAPS_ENTRY_SIZE(E) \
    ((size_t) ((E)->vm_end - (E)->vm_start))
#define UTIL_PROC_MAPS_ENTRY_IS_PROT(E, S) \
    ((E)->r == S[0] && (E)->w == S[1] && (E)->x == S[2])
#define UTIL_PROC_MAPS_ENTRY_SET_PROT(E, S) \
    do { (E)->r = S[0]; (E)->w = S[1]; (E)->x = S[2]; } while(0)
#define UTIL_PROC_MAPS_ENTRY_IS_SHARED(E) \
    ((E)->s == 's')
#define UTIL_PROC_MAPS_ENTRY_SET_SHARED(E, S) \
    ((E)->s = (S) ? 's' : 'p')
#define UTIL_PROC_MAPS_ENTRY_NAME_EQUALS_STR(E, N) \
    (!strcmp((E)->name, N))
#define UTIL_PROC_MAPS_ENTRY_NAME_STARTS(E, N) \
    (!strncmp((E)->name, N, strlen(N)))
#define UTIL_PROC_MAPS_ENTRY_NAME_CONTAINS(E, N) \
    (strstr((E)->name, N))

#define UTIL_PROC_MAPS_ENTRY_IS_PROG(E) \
    (UTIL_PROC_MAPS_ENTRY_IS_PROG_TEXT(E) || \
    UTIL_PROC_MAPS_ENTRY_IS_PROG_RO(E) || \
    UTIL_PROC_MAPS_ENTRY_IS_PROG_DATA(E))

#define UTIL_PROC_MAPS_ENTRY_IS_PROG_TEXT(E) \
    (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, UTIL_PROC_MAPS_PROG_TEXT_ADDR))
#define UTIL_PROC_MAPS_ENTRY_IS_PROG_RO(E) \
    (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, UTIL_PROC_MAPS_PROG_RO_ADDR))
#define UTIL_PROC_MAPS_ENTRY_IS_PROG_DATA(E) \
    (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, UTIL_PROC_MAPS_PROG_DATA_ADDR))
#define UTIL_PROC_MAPS_ENTRY_IS_TLS(E) \
    (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, UTIL_PROC_MAPS_TLS_ADDR))

#define UTIL_PROC_MAPS_ENTRY_IS_ANON(E) \
    UTIL_PROC_MAPS_ENTRY_NAME_EQUALS_STR(E, __ANON)
#define UTIL_PROC_MAPS_ENTRY_IS_HEAP(E) \
    (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(E, UTIL_PROC_MAPS_HEAP_ADDR))
#define UTIL_PROC_MAPS_ENTRY_IS_STACK(E) \
    UTIL_PROC_MAPS_ENTRY_NAME_STARTS(E, "[stack")
#define UTIL_PROC_MAPS_ENTRY_IS_VDSO(E) \
    UTIL_PROC_MAPS_ENTRY_NAME_EQUALS_STR(E, __VDSO)
#define UTIL_PROC_MAPS_ENTRY_IS_VSYSCALL(E) \
    UTIL_PROC_MAPS_ENTRY_NAME_EQUALS_STR(E, __VSYSCALL)
#define UTIL_PROC_MAPS_ENTRY_IS_LIB(E) \
    (UTIL_PROC_MAPS_ENTRY_NAME_STARTS(E, "/lib/") || \
    UTIL_PROC_MAPS_ENTRY_NAME_STARTS(E, "/usr/lib/"))
#define UTIL_PROC_MAPS_ENTRY_IS_LIB_BSS(E) \
    (UTIL_PROC_MAPS_ENTRY_IS_ANON(E) && UTIL_PROC_MAPS_ENTRY_IS_LIB((E)-1))
#define UTIL_PROC_MAPS_ENTRY_PARENT_LIB(E) \
    (UTIL_PROC_MAPS_ENTRY_IS_LIB(E) ? (E) : \
    UTIL_PROC_MAPS_ENTRY_IS_LIB_BSS(E) ? (E)-1 : NULL)
#define UTIL_PROC_MAPS_ENTRY_IS_FILE(E) \
    (UTIL_PROC_MAPS_ENTRY_NAME_STARTS(E, "/"))
#define UTIL_PROC_MAPS_ENTRY_IS_MMAP(E) \
    (UTIL_PROC_MAPS_ENTRY_IS_ANON(E) || UTIL_PROC_MAPS_ENTRY_IS_LIB(E))

#define UTIL_PROC_MAPS_ITER(M, E, SA, EA, B) do { \
    int __i; \
    if (!(EA)) { \
        EA = (typeof(EA)) ULONG_MAX; \
    } \
    util_proc_maps_entry_t __IE = { .vm_start = (unsigned long) SA, \
        .vm_end = (unsigned long) EA};\
    for (__i=0;__i<(M)->num_entries;__i++) { \
        E = &(M)->entries[__i]; \
        if (UTIL_PROC_MAPS_ENTRY_OVERLAPS(E, &__IE)) { \
            B \
        } \
    } \
} while(0)

static inline void util_proc_maps_entry_remove(util_proc_maps_t *maps,
    util_proc_maps_entry_t *entry)
{
    long i = entry - maps->entries;
    assert(i >= 0 && i < maps->num_entries);
    if (i < maps->num_entries-1) {
        memmove(&maps->entries[i], &maps->entries[i+1],
            sizeof(util_proc_maps_entry_t)*(maps->num_entries-i-1));
    }
    maps->num_entries--;
}

static inline int util_proc_maps_entry_mapped(util_proc_maps_entry_t *entry)
{
    int ret = mincore((void*) entry->vm_start, PAGE_SIZE, NULL);
    assert(ret != 0);
    if (errno == ENOMEM) {
        return 0;
    }
    assert(errno == EFAULT);
    return 1;
}

static inline void util_proc_maps_remove_unmapped(util_proc_maps_t *maps)
{
    int i, ret;
    for (i=0;i<maps->num_entries;i++) {
        util_proc_maps_entry_t *entry = &maps->entries[i];
        ret = util_proc_maps_entry_mapped(entry);
        if (!ret) {
            util_proc_maps_entry_remove(maps, entry);
            i--;
        }
    }
}

static inline int util_proc_maps_parse_filter(pid_t pid, util_proc_maps_t *maps,
    util_proc_maps_parse_cb_t cb, void* cb_args)
{
    int fd;
    char buf[5000];
    int num_entries = 0;
    int ret = 0, stop = 0;

    // Our own buffered I/O bookkeeping
    char _iobuf[5000];
    read_buffer_t iobuf;
    iobuf.start = _iobuf;
    iobuf.end   = _iobuf + sizeof(_iobuf) - 1;
    iobuf.ptr   = _iobuf + sizeof(_iobuf) - 1; // initialize i/o ptr at end

    sprintf(buf, "/proc/%d/maps", pid);
    fd = open(buf, O_RDONLY);
    if (fd == -1) {
        return -ENOENT;
    }

    memset(maps, 0, sizeof(util_proc_maps_t));
    maps->pid = pid;

    while (!stop && bufread(fd, buf, sizeof(buf), &iobuf) > 0) {
        util_proc_maps_entry_t maps_entry;
        int n;

        maps_entry.name[0] = '\0';
        maps_entry.buff = NULL;
        maps_entry.owner = maps;
        n = sscanf(buf, "%lx-%lx %c%c%c%c %llx %x:%x %lu %s",
            &maps_entry.vm_start, &maps_entry.vm_end,
            &maps_entry.r, &maps_entry.w, &maps_entry.x, &maps_entry.s,
            &maps_entry.pgoff, &maps_entry.major, &maps_entry.minor,
            &maps_entry.ino, maps_entry.name);
        if (n < 10) {
            ret = -EINVAL;
            goto out;
        }
        if (cb) {
            ret = cb(&maps_entry, cb_args);
            switch (ret) {
            case UTIL_PROC_MAPS_RET_SAVE:
                break;
            case UTIL_PROC_MAPS_RET_SAVE_AND_STOP:
                stop = 1;
                break;
            case UTIL_PROC_MAPS_RET_CONTINUE:
                goto next;
            case UTIL_PROC_MAPS_RET_STOP:
                ret = 0;
                goto out;
            default:
                ret = -ENOENT;
                goto out;
            }
        }

        if (num_entries+1 > maps->num_entries) {
            maps->num_entries = (maps->num_entries+1)*2;
            maps->entries = realloc(maps->entries,
                sizeof(util_proc_maps_entry_t)*maps->num_entries);
            assert(maps->entries);
        }
        maps->entries[num_entries] = maps_entry;
        num_entries++;
next:
        ret = 0;
    }

out:
    close(fd);
    if (ret != 0) {
        num_entries = 0;
    }
    maps->num_entries = num_entries;
    if (ret == 0) {
        /* Remove stale libc state. */
        util_proc_maps_remove_unmapped(maps);
    }
    maps->entries = realloc(maps->entries,
        sizeof(util_proc_maps_entry_t)*maps->num_entries);

    if (ret != 0 && maps->entries)
        free(maps->entries);

    return ret;
}

static inline int util_proc_maps_parse(pid_t pid, util_proc_maps_t *maps)
{
    return util_proc_maps_parse_filter(pid, maps, NULL, NULL);
}

static inline void util_proc_maps_get_info(util_proc_maps_t *maps,
    util_proc_maps_info_t *info)
{
    int i, num_entries = 4;
    util_proc_maps_entry_t *first_lib = NULL;
    util_proc_maps_entry_t *last_lib = NULL;
    util_proc_maps_entry_t *first_mmap = NULL;
    util_proc_maps_entry_t *last_mmap = NULL;

    memset(info, 0, sizeof(util_proc_maps_info_t));
    for (i=0;i<maps->num_entries;i++) {
        int skip = 0;
        util_proc_maps_entry_t *entry = &maps->entries[i];
        if (UTIL_PROC_MAPS_ENTRY_IS_LIB(entry)) {
            if (!first_lib)
                first_lib = entry;
            last_lib = entry;
            skip = 1;
        }
        if (UTIL_PROC_MAPS_ENTRY_IS_MMAP(entry)) {
            if (!first_mmap)
                first_mmap = entry;
            skip = 1;
        }
        else {
            if (first_mmap && !last_mmap)
                last_mmap = entry-1;
        }
        if (skip)
            continue;
        if (!info->prog_text && UTIL_PROC_MAPS_ENTRY_IS_PROG_TEXT(entry)) {
            info->prog_text = entry;
            num_entries++;
            continue;
        }
        if (!info->prog_ro && UTIL_PROC_MAPS_ENTRY_IS_PROG_RO(entry)) {
            info->prog_ro = entry;
            num_entries++;
            continue;
        }
        if (!info->prog_data && UTIL_PROC_MAPS_ENTRY_IS_PROG_DATA(entry)) {
            info->prog_data = entry;
            num_entries++;
            continue;
        }
        if (!info->heap && UTIL_PROC_MAPS_ENTRY_IS_HEAP(entry)) {
            info->heap = entry;
            num_entries++;
            continue;
        }
        if (!info->stack && UTIL_PROC_MAPS_ENTRY_IS_STACK(entry)) {
            info->stack = entry;
            num_entries++;
            continue;
        }
        if (!info->vdso && UTIL_PROC_MAPS_ENTRY_IS_VDSO(entry)) {
            info->vdso = entry;
            num_entries++;
            continue;
        }
        if (!info->vsyscall && UTIL_PROC_MAPS_ENTRY_IS_VSYSCALL(entry)) {
            info->vsyscall = entry;
            num_entries++;
            continue;
        }
    }

    sprintf(info->vm.name, "%s", "[vm]");
    info->vm.owner = maps;
    info->vm.vm_start = maps->entries[0].vm_start;
    info->vm.vm_end = maps->entries[maps->num_entries-1].vm_end;
    UTIL_PROC_MAPS_ENTRY_SET_PROT(&info->vm, "rwx");
    UTIL_PROC_MAPS_ENTRY_SET_SHARED(&info->vm, 0);

    sprintf(info->prog.name, "%s", "[prog]");
    info->prog.owner = maps;
    info->prog.vm_start = info->prog_text ? info->prog_text->vm_start : 0;
    info->prog.vm_end = info->prog_data ? info->prog_data->vm_end : 0;
    UTIL_PROC_MAPS_ENTRY_SET_PROT(&info->prog, "rwx");
    UTIL_PROC_MAPS_ENTRY_SET_SHARED(&info->prog, 0);

    sprintf(info->mmap.name, "%s", "[mmap]");
    info->mmap.owner = maps;
    info->mmap.vm_start = first_mmap ? first_mmap->vm_start : 0;
    info->mmap.vm_end = last_mmap ? last_mmap->vm_end : 0;
    UTIL_PROC_MAPS_ENTRY_SET_PROT(&info->mmap, "rwx");
    UTIL_PROC_MAPS_ENTRY_SET_SHARED(&info->mmap, 0);

    sprintf(info->libs.name, "%s", "[libs]");
    info->libs.owner = maps;
    info->libs.vm_start = first_lib ? first_lib->vm_start : 0;
    info->libs.vm_end = last_lib ? last_lib->vm_end : 0;
    if (info->libs.vm_end && info->libs.vm_end < info->vm.vm_end
        && (last_lib+1)->vm_start == info->libs.vm_end) {
        last_lib++;
        if (UTIL_PROC_MAPS_ENTRY_IS_ANON(last_lib)) {
            info->libs.vm_end = last_lib->vm_end;
        }
    }
    UTIL_PROC_MAPS_ENTRY_SET_PROT(&info->libs, "rwx");
    UTIL_PROC_MAPS_ENTRY_SET_SHARED(&info->libs, 1);

    info->maps.pid = maps->pid;
    info->maps.num_entries = num_entries;
    info->maps.entries = info->maps_entries;
    i = 0;
    info->maps.entries[i++] = info->vm;
    info->maps.entries[i++] = info->prog;
    info->maps.entries[i++] = info->mmap;
    info->maps.entries[i++] = info->libs;
    if (info->prog_text)
        info->maps.entries[i++] = *info->prog_text;
    if (info->prog_ro)
        info->maps.entries[i++] = *info->prog_ro;
    if (info->prog_data)
        info->maps.entries[i++] = *info->prog_data;
    if (info->heap)
        info->maps.entries[i++] = *info->heap;
    if (info->stack)
        info->maps.entries[i++] = *info->stack;
    if (info->vdso)
        info->maps.entries[i++] = *info->vdso;
    if (info->vsyscall)
        info->maps.entries[i++] = *info->vsyscall;
    assert(i == num_entries);
}

static inline void util_proc_maps_destroy(util_proc_maps_t *maps)
{
    free(maps->entries);
    memset(maps, 0, sizeof(util_proc_maps_t));
}

static inline util_proc_maps_entry_t* util_proc_maps_lookup_by_name(
    util_proc_maps_t *maps, const char *name)
{
    int i;

    for (i=0;i<maps->num_entries;i++) {
        if (UTIL_PROC_MAPS_ENTRY_NAME_EQUALS_STR(&maps->entries[i], name)) {
            return &maps->entries[i];
        }
    }

    return NULL;
}

static inline util_proc_maps_entry_t* util_proc_maps_lookup_by_addr(
    util_proc_maps_t *maps, unsigned long addr)
{
    int i;

    for (i=0;i<maps->num_entries;i++) {
        if (UTIL_PROC_MAPS_ENTRY_CONTAINS_ADDR(&maps->entries[i], addr)) {
            return &maps->entries[i];
        }
    }

    return NULL;
}

static inline util_proc_maps_entry_t* util_proc_maps_lookup_by_prev(
    util_proc_maps_t *maps, util_proc_maps_entry_t *prev)
{
    int i;

    for (i=1;i<maps->num_entries;i++) {
        if (&maps->entries[i-1] == prev) {
            return &maps->entries[i];
        }
    }

    return NULL;
}

static inline void util_proc_maps_entry_print(util_proc_maps_entry_t *entry)
{
    _UTIL_PRINTF("%08lx-%08lx %c%c%c%c %08llx %02x:%02x %-10lu %s",
        entry->vm_start, entry->vm_end,
        entry->r, entry->w, entry->x, entry->s,
        entry->pgoff, entry->major, entry->minor,
        entry->ino, entry->name);
}

static inline void util_proc_maps_print(util_proc_maps_t *maps)
{
    int i;

    for (i=0;i<maps->num_entries;i++) {
        util_proc_maps_entry_print(&maps->entries[i]);
        _UTIL_PRINTF("\n");
    }
}

static inline void util_proc_maps_dump(pid_t pid)
{
    int ret;
    util_proc_maps_t maps;

    ret = util_proc_maps_parse(pid, &maps);
    assert(ret == 0);
    util_proc_maps_print(&maps);
    util_proc_maps_destroy(&maps);
}

static inline void util_proc_maps_info_print(util_proc_maps_info_t *info)
{
    util_proc_maps_print(&info->maps);
}

static inline void util_proc_maps_entry_unmap(util_proc_maps_entry_t *entry)
{
    if (entry->buff) {
        munmap(entry->buff, UTIL_PROC_MAPS_ENTRY_SIZE(entry));
        entry->buff = NULL;
    }
}

static inline int util_proc_maps_entry_map(util_proc_maps_entry_t *entry)
{
    int fd, ret = 0;
    char mem_path[128];
    size_t size;
    pid_t pid = entry->owner->pid;

    size = UTIL_PROC_MAPS_ENTRY_SIZE(entry);
    entry->buff = mmap(NULL, size, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, 0, 0);
    if (entry->buff == MAP_FAILED) {
        return -1;
    }
    if (entry->r != 'r') {
        return 0;
    }
    if (pid == getpid()) {
        memcpy(entry->buff, (void*) entry->vm_start, size);
        return 0;
    }

    sprintf(mem_path, "/proc/%d/mem", pid);
    fd = open(mem_path, O_RDONLY);
    if (fd < 0) {
        ret = -2;
        goto out;
    }

    do {
        long pos = lseek64(fd, entry->vm_start, SEEK_SET);
        if (pos == (long)-1) {
            ret = -3;
            goto out;
        }
        ret = read(fd, entry->buff, size);
    } while(ret != size && errno == EINTR);
    ret = ret == size ? 0 : -4;

out:
    if (ret)
        util_proc_maps_entry_unmap(entry);
    if (fd > 0)
        close(fd);
    return ret;
}


static inline int util_proc_maps_entry_data_diff(util_proc_maps_entry_t *e,
    util_proc_maps_entry_t *e2, size_t off, size_t off2, size_t size)
{
    int ret;

    if (size+off > UTIL_PROC_MAPS_ENTRY_SIZE(e)
        || size+off2 > UTIL_PROC_MAPS_ENTRY_SIZE(e2)) {
        return -1;
    }

    ret = util_proc_maps_entry_map(e);
    if (ret) {
        return -2;
    }
    ret = util_proc_maps_entry_map(e2);
    if (ret) {
        util_proc_maps_entry_unmap(e);
        return -3;
    }
    ret = !!memcmp(e->buff+off, e2->buff+off2, size);

    util_proc_maps_entry_unmap(e);
    util_proc_maps_entry_unmap(e2);
    return ret;
}

static inline int util_proc_maps_entry_diff(util_proc_maps_entry_t *e,
    util_proc_maps_entry_t *e2, unsigned long start, unsigned long end,
    int flags)
{
    if (!end)
        end = ULONG_MAX;

    if (!e || !e2)
        return flags & DIFF_FLAG(ALLOW_NO_ENTRY) ? 0 :
            DIFF_FLAG(ALLOW_NO_ENTRY);

    if (!UTIL_PROC_MAPS_ENTRY_NAME_EQUALS(e, e2) &&
        !(flags & DIFF_FLAG(ALLOW_NAME_DIFF)))
        return DIFF_FLAG(ALLOW_NAME_DIFF);

    if (!UTIL_PROC_MAPS_ENTRY_PROT_EQUALS(e, e2) &&
        !(flags & DIFF_FLAG(ALLOW_PROT_DIFF)))
        return DIFF_FLAG(ALLOW_PROT_DIFF);

    if (!UTIL_PROC_MAPS_ENTRY_SHARED_EQUALS(e, e2) &&
        !(flags & DIFF_FLAG(ALLOW_SHARED_DIFF)))
        return DIFF_FLAG(ALLOW_SHARED_DIFF);

    if (!UTIL_PROC_MAPS_ENTRY_OVERLAPS(e, e2))
        return flags & DIFF_FLAG(ALLOW_RANGE_MISMATCH) ? 0 :
            DIFF_FLAG(ALLOW_RANGE_MISMATCH);

    if (!UTIL_PROC_MAPS_ENTRY_RANGE_EQUALS(e, e2)) {
        if (!(flags & DIFF_FLAG(ALLOW_RANGE_DIFF))) {
            return DIFF_FLAG(ALLOW_RANGE_DIFF);
        }
    }

    start = MAX(MAX(start, e->vm_start), e2->vm_start);
    end = MIN(MIN(end, e->vm_end), e2->vm_end);
    if (start >= end) {
        return -11;
    }

    if (flags & DIFF_FLAG(ALLOW_DATA_DIFF)) {
        return 0;
    }

    return util_proc_maps_entry_data_diff(e, e2,
        start-e->vm_start, start-e2->vm_start, end-start);
}

static inline int util_proc_maps_diff(util_proc_maps_t *maps,
    util_proc_maps_t *maps2, unsigned long start, unsigned long end,
    int flags, util_proc_maps_diff_cb_t cb, void *cb_args)
{
    int ret, hasdiff = 0;
    util_proc_maps_entry_t *entry, *entry2;
    unsigned long entry_start, entry_end;

    UTIL_PROC_MAPS_ITER(maps, entry, start, end,
        entry_start = MAX(start, entry->vm_start);
        entry_end = MIN(end, entry->vm_end);
        entry2 = util_proc_maps_lookup_by_addr(maps2, entry_start);
        if (!entry2) {
            entry2 = util_proc_maps_lookup_by_addr(maps2, entry_end);
        }
        ret = util_proc_maps_entry_diff(entry, entry2, entry_start, entry_end, flags);
        if (!cb) {
            if (ret)
                return ret;
        } else {
            ret = cb(entry, entry2, ret, cb_args);
            if (ret < 0)
                return ret;
            if (ret > 0)
                hasdiff = 1;
        }
    );

    return hasdiff;
}

#endif /* _UTIL_PROC_MAPS_H */

