#ifndef CFI_H
#define CFI_H
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <asm/prctl.h>
#include <sys/prctl.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE		4096
#endif

#define CFI_SFI_BASE		0x080000000000
//				  ^   ^   ^	
#define CFI_SHADOW_DISTANCE	4111	// this is a prime number
#define CFI_LABEL_OFFSET        8
#define CFI_EMULATION_LABEL     0xCF1600DC0DE
#define CFI_MAX_CALL_DEPTH      20 * 1024 * PAGE_SIZE
#define CFI_MAX_THREADS		0x4000
#define CFI_STACK_IN_USE	0x1
#define CFI_STACK_NOT_IN_USE	0x0
#define CFI_INVALID		0xFFFFFFFFFFFFFFFF
#define CFI_CURRENT_STACK_INDEX	shadow_stack_current
#define CFI_CALL_INST_SIZE	4	// TODO: Calculate this properly
#define CFI_DBG(...)		;


#define CFI_BDBG(...)		;
/*#define CFI_BDBG(...)		\
	printf("%s:%d %s ", __FILE__, __LINE__, __func__); \
	printf(__VA_ARGS__);
*/
#define CFI_RDRAND_SUCCESS	0
#define CFI_RDRAND_FAILURE	1

#define XMM_CFI			0

#define XMM_FROM_VAR(xmm_n, v) \
    __asm__ __volatile__ ( \
            "movdqa %0, %%xmm" xmm_n " \n\t" \
            : \
            : "x"(v) \
            : "xmm" xmm_n);

#define XMM_TO_VAR(xmm_n, v) \
    __asm__ __volatile__ ( \
            "movdqa %%xmm" xmm_n ", %0 \n\t" \
            : "=x"(v) \
            : \
            : "xmm" xmm_n);

//arch_prctl(ARCH_SET_GS, V)
#ifdef CFI_USE_FSGS
#define SET_SHADOW_BASE_REG(V) \
	asm volatile ( "movq %0, %%fs:0" : : "r"(V):);
#else
#define SET_SHADOW_BASE_REG(V)  \
	shadow_return_stack = V; 
#endif

#ifdef CFI_USE_FSGS
#define GET_SHADOW_BASE_REG(V) \
	asm volatile ( "movq %%fs:0, %0" : "=r"(V):: );
#else
#define GET_SHADOW_BASE_REG(V) \
		V = shadow_return_stack; 
#endif

#ifdef USE_PTHREAD_LOCKING
#define PTHREAD_LOCK(V)		pthread_mutex_lock(V)
#define PTHREAD_UNLOCK(V)	pthread_mutex_unlock(V)
#else
#define PTHREAD_LOCK(V)		;
#define PTHREAD_UNLOCK(V)	;
#endif

typedef unsigned shadow_stacks_index_t;
typedef uint64_t addr_t;

typedef struct {
	addr_t reg_stack_pointer; // rsp
	addr_t return_addr;	
} shadow_return_t;

typedef struct {
	uint64_t top;
	unsigned flag;
	shadow_return_t returns_stack[CFI_MAX_CALL_DEPTH];
} shadow_return_stack_t;


void inline cfi_shadow_init();
void inline cfi_fwd_edge_check(addr_t ptr);
void inline cfi_bk_shadow_func_entry();
void inline cfi_bk_shadow_func_exit();

#endif
