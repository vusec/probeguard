#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <assert.h>

#define RDEF_MAX_ALLOC_LIMIT 	(0x80000ULL)	// SPECCPU2006 soplex does malloc for 100000 ints
#define RDEF_MAX_SIZE_LIKE_ARGS	10

static uint64_t size_like_args[RDEF_MAX_SIZE_LIKE_ARGS];

// Alloc func family
extern void * malloc(size_t size);
extern void * calloc(size_t nmemb, size_t size);
extern void * realloc(void *ptr, size_t size);
extern void * valloc(size_t size);
extern void brk(void *addr);
extern void * sbrk(intptr_t increment);
extern void * memalign(size_t alignment, size_t size);
extern int posix_memalign(void **memptr, size_t alignment, size_t size);
extern void * mmap(void *start, size_t length, int prot, int flags, int fd, off_t offset);
extern void * mmap64(void *start, size_t length, int prot, int flags, int fd, off64_t offset);
extern void *mremap(void *old_address, size_t old_size, size_t new_size, int flags, ... /* void *new_address */);

void allocguard_call_check(uint64_t size)
{
#ifdef FOR_SPEC		// soplex fails otherwise
  assert(size >= 0); 	// povray uses size==0
#else
  assert(size < RDEF_MAX_ALLOC_LIMIT);
#endif
}

void allocguard_calloc_call_check(size_t nmemb, size_t size)
{
#ifdef FOR_SPEC 	// mcf fails otherwise
  assert(nmemb * size > 0);
#else
  assert(nmemb * size < RDEF_MAX_ALLOC_LIMIT);
#endif
}

void allocguard_brk_call_check(void *addr)
{
  assert((uint64_t)addr - (uint64_t)sbrk(0) < RDEF_MAX_ALLOC_LIMIT);
}

void allocguard_icall_check(void *target_addr, unsigned num_sizes)
{
  int size_arg_pos = 100;
  int match_found = 0;
  uint64_t *size_args = &size_like_args[0];

	if ((void*)malloc == (void*)target_addr) {
		size_arg_pos = 0;
		match_found = 1;
	} else if ((void*)calloc == (void*)target_addr) {
		/* special case */
		if (num_sizes >= 2) {
		   assert(size_args[0] * size_args[1] < RDEF_MAX_ALLOC_LIMIT && "AllocGuard threshold breach.");
		}
	} else if ((void*)realloc == (void*)target_addr) {
		size_arg_pos = 0;
		match_found = 1;
	} else if ((void*)memalign == (void*)target_addr) {
		size_arg_pos = 1;
		match_found = 1;
	} else if ((void*)posix_memalign == (void*)target_addr) {
		size_arg_pos = 1;
		match_found = 1;
	} else if ((void*)mmap == (void*)target_addr) {
		size_arg_pos = 0;
		match_found = 1;
	} else if ((void*)mmap64 == (void*)target_addr) {
		size_arg_pos = 0;
		match_found = 1;
	} else if ((void*)mremap == (void*)target_addr) {
		size_arg_pos = 1;
		match_found = 1;
	} else if ((void*)valloc == (void*)target_addr) {
		size_arg_pos = 0;
		match_found = 1;
	} else if ((void*)brk == (void*)target_addr) {
		/* special case */
		if (num_sizes >= 1) {
		   assert ((uint64_t)size_args[0] - (uint64_t)sbrk(0) < RDEF_MAX_ALLOC_LIMIT && "AllocGuard threshold breach.");
		}
	} else if ((void*)sbrk == (void*)target_addr) {
		size_arg_pos = 0;
		match_found = 1;
  	}
   if (!match_found)
	return;
   if (size_arg_pos < num_sizes) {
	assert(size_args[size_arg_pos] < RDEF_MAX_ALLOC_LIMIT && "AllocGuard threshold breach.");
   }
   return;
}

