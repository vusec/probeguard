#ifndef _UTIL_SHMEM_H
#define _UTIL_SHMEM_H

#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef UTIL_SHMEM_USE_SHM_OPEN
/* When 0, program may need root or CAP_IPC_OWNER for shmat(). */
#define UTIL_SHMEM_USE_SHM_OPEN 1
#endif

typedef struct util_shmem_seg_s {
    char name[NAME_MAX+1];
    void *addr;
    size_t size;
    int id;
} util_shmem_seg_t;

static inline int util_shmem_open_new(util_shmem_seg_t *seg)
{
    int ret, shmfd;

    shmfd = shm_open(seg->name, O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
    if (shmfd == -1) {
        return -1;
    }
    ret = ftruncate(shmfd, seg->size);
    if (ret == -1) {
        shm_unlink(seg->name);
        return -1;
    }
    seg->id = shmfd;

    return 0;
}

static inline int util_shmem_open_attach(util_shmem_seg_t *seg,
    int fixed)
{
    void *addr = NULL;
    int flags = MAP_SHARED;

    if (fixed) {
        addr = seg->addr;
        flags |= MAP_FIXED;
    }

    addr = mmap(addr, seg->size, PROT_READ|PROT_WRITE,
        flags, seg->id, 0);
    if (addr == MAP_FAILED) {
        return -1;
    }
    seg->addr = addr;

    return 0;
}

static inline int util_shmem_open_detach(util_shmem_seg_t *seg)
{
    return munmap(seg->addr, seg->size);
}

static inline int util_shmem_open_del(util_shmem_seg_t *seg)
{
    return shm_unlink(seg->name);
}

static inline int util_shmem_svipc_new(util_shmem_seg_t *seg)
{
    int shmid;

    shmid = shmget(IPC_PRIVATE, seg->size, IPC_CREAT|O_RDWR);
    if (shmid == 1) {
        return -1;
    }
    seg->id = shmid;

    return 0;
}

static inline int util_shmem_svipc_attach(util_shmem_seg_t *seg,
    int fixed)
{
    void *addr = NULL;
    int flags = 0;

    if (fixed) {
        addr = seg->addr;
        flags |= SHM_REMAP;
    }

    addr = shmat(seg->id, addr, flags);
    if (addr == (void*)-1) {
        return -1;
    }
    seg->addr = addr;

    return 0;
}

static inline int util_shmem_svipc_detach(util_shmem_seg_t *seg)
{
    return shmdt(seg->addr);
}

static inline int util_shmem_svipc_del(util_shmem_seg_t *seg)
{
    return shmctl(seg->id, IPC_RMID, NULL);
}

static inline int util_shmem_svipc_share(util_shmem_seg_t *seg,
    int fixed)
{
    int i, shmid;
    char *addr;
    char *buff;

    buff = mmap(NULL, seg->size, PROT_READ|PROT_WRITE,
        MAP_PRIVATE|MAP_ANON, 0, 0);
    memcpy(buff, seg->addr, seg->size);
    shmid = shmget(IPC_PRIVATE, seg->size, IPC_CREAT|O_RDWR);
    if (shmid == 1) {
        munmap(buff, seg->size);
        return -1;
    }
    addr = (char*) shmat(shmid, seg->addr, SHM_REMAP);
    if (addr != seg->addr) {
        munmap(buff, seg->size);
        return -1;
    }
    for (i=0;i<seg->size;i++) {
        addr[i] = buff[i];
    }
    munmap(buff, seg->size);

    seg->addr = addr;
    seg->id = shmid;
    return 0;
}

static inline int util_shmem_svipc_unshare(util_shmem_seg_t *seg)
{
    return shmdt(seg->addr);
}

/* Generic shmem interface. */
static inline int util_shmem_new(util_shmem_seg_t *seg)
{
#if UTIL_SHMEM_USE_SHM_OPEN
    return util_shmem_open_new(seg);
#else
    return util_shmem_svipc_new(seg);
#endif
}

static inline int util_shmem_attach(util_shmem_seg_t *seg,
    int fixed)
{
#if UTIL_SHMEM_USE_SHM_OPEN
    return util_shmem_open_attach(seg, fixed);
#else
    return util_shmem_svipc_attach(seg, fixed);
#endif
}

static inline int util_shmem_detach(util_shmem_seg_t *seg)
{
#if UTIL_SHMEM_USE_SHM_OPEN
    return util_shmem_open_detach(seg);
#else
    return util_shmem_svipc_detach(seg);
#endif
}

static inline int util_shmem_del(util_shmem_seg_t *seg)
{
#if UTIL_SHMEM_USE_SHM_OPEN
    return util_shmem_open_del(seg);
#else
    return util_shmem_svipc_del(seg);
#endif
}

static inline int util_shmem_share(util_shmem_seg_t *seg,
    int attach, int fixed)
{
    void *addr = seg->addr;
    int ret;

    ret = util_shmem_new(seg);
    if (ret) {
        return ret;
    }
    ret = util_shmem_attach(seg, 0);
    if (ret) {
        util_shmem_del(seg);
        errno = ENOMEM;
        return -1;
    }
    memcpy(seg->addr, addr, seg->size);
    if (!attach) {
        util_shmem_detach(seg);
        return 0;
    }
    if (fixed) {
        util_shmem_detach(seg);
        seg->addr = addr;
        ret = util_shmem_attach(seg, 1);
        if (ret) {
            util_shmem_del(seg);
            errno = ENOMEM;
            return -1;
        }
    }

    return 0;
}

#endif /* _UTIL_SHMEM_H */

