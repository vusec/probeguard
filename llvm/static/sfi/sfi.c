#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sfi.h>

#ifdef HAVE_LIBDUNE
#include <sys/mman.h>
//#include "libdune/dune.h"
#define DUNE_VMCALL_SECRET_MAPPING_ADD 512
#endif

#define PASS_VAR volatile __attribute__((used))
#define PASS_FUNC __attribute__((used))

bool mpx_init_for_process(void);

/* Set by the pass. */
PASS_VAR int sfi_type = -1;
PASS_VAR int sfi_points = -1;

/*
 * Generating lib func -> syscall mapping
 */

PASS_FUNC void sfi_before_libcall(char *name)
{
    syscall(450, name);
}

/*
 * Software-based SFI
 */
PASS_FUNC void* sfi_soft_begin(void *ptr)
{
    return (void*) (((uintptr_t)ptr) & SFI_MASK);
}

/*
 * MPX-based SFI
 */
void sfi_mpx_init()
{
    mpx_init_for_process();
#if LLVM_HAS_MPX
    long sfi_lb=0, sfi_ub=SFI_MASK;
    __asm__("bndmk (%0,%1), %%bnd0"
        :
        : "r"(sfi_lb), "r"(sfi_ub)
        :
        );
#endif
}
PASS_FUNC void* sfi_mpx_begin(void *ptr)
{
#if LLVM_HAS_MPX
    __asm__ __volatile__ (
            "bndcu %0, %%bnd0 \n\t"
            //"bndcl %0, %%bnd0 \n\t"
            :
            : "r" (ptr));
#endif
    return ptr;
}

/*
 * MPK simulate
 */
PASS_FUNC void sfi_mpk_begin(int domain)
{
	__asm__ __volatile__(
			"movq %%xmm14, %%r14\n\t"
			"not %%r13\n\t"
			"movq %%r14, %%xmm14\n\t"
            "mfence\n\t"
			:::"%r14", "%r13");
}
PASS_FUNC void sfi_mpk_end(void)
{
	__asm__ __volatile__(
			"movq %%xmm14, %%r14\n\t"
			"not %%r13\n\t"
			"movq %%r14, %%xmm14\n\t"
            "mfence\n\t"
			:::"%r14", "%r13");
}

#ifdef HAVE_LIBDUNE
#define vmfunc_switch(mapping)                                                 \
    __asm__ __volatile__(                                                      \
            "mov $0, %%eax \n\t" /* vmfunc number (0=eptp switch) */           \
            "mov %0, %%ecx \n\t" /* eptp index */                              \
            "vmfunc \n\t"                                                      \
            :                                                                  \
            : "r"(mapping)                                                     \
            : "%rax", "%rcx", "memory");

/*
 * VMFUNC using Dune.
 */
PASS_FUNC void *vmfunc_secure_malloc(size_t len)
{
    void *pages;
    int pgz = sysconf(_SC_PAGESIZE);

    len += sizeof(len); /* Keep administration of alloc in page as well. */
    len = (len & ~(pgz - 1)) + pgz;
    pages = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
            0, 0);
    if (pages == MAP_FAILED)
    {
        perror("secure_malloc");
        return NULL;
    }
    syscall(DUNE_VMCALL_SECRET_MAPPING_ADD, pages, len);

    //printf("SALLOC %zu @ %p\n", len, pages);

    /* XXX we dump len in front of alloc and shift the returned addr by
     * sizeof(size_t). is it bad allocations are (slightly) not page aligned? */
    *((size_t *)pages) = len;

    return (size_t*)pages + 1;
}
PASS_FUNC void vmfunc_secure_free(void *p)
{
    int ret;
    void *pages = ((size_t *)p - 1);
    size_t len = *(size_t *)pages;
    //printf("SFREE %zu @ %p\n", len, pages);

    ret = munmap(p, len);
    if (ret == -1)
        perror("secure_free");
}
#endif

void sfi_vmfunc_init()
{
#ifndef HAVE_LIBDUNE
    fprintf(stderr, "ERROR: Dune was not enabled in llvm-apps during "
            "compilation, cannot use VMFUNC\n");
#else
    printf("NOTE: please run this under dune's sandbox, otherwise an illegal instruction exception will be thrown.\n");
    printf(" e.g. ~/dune/apps/sandbox/sandbox /lib64/ld-linux-x86-64.so.2 path/to/app\n");
#endif
}

#ifdef HAVE_LIBDUNE
PASS_FUNC void sfi_vmfunc_begin(int mapping)
{
    vmfunc_switch(mapping);
}
PASS_FUNC void sfi_vmfunc_end(void)
{
    vmfunc_switch(0);
}
#endif

void sfi_crypt_init();

__attribute__((constructor))
void sfi_init() {
    /* No instrumentation, no party. */
    if (sfi_type < -1 || sfi_points < -1)
        return;

    switch (sfi_type) {
    case MPX:
        sfi_mpx_init();
    break;

    case VMFUNC:
        sfi_vmfunc_init();
    break;

    case CRYPT:
        sfi_crypt_init();
    break;
    }
}

