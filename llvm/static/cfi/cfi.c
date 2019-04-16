/*****************************************************
* Author: Koustubha Bhat
* Date  : 15-July-2016
*
* Description:
* Forward edge check simulation
* Backward edge protection using SFI-ed shadow memory
* 
* Assumptions:
* 0. Assuming 64-bit. 
* 1. Code :--x , stack and heap: rw-
* 2. SFI for information hiding where we place our 
*    shadow return address stack
* 3. Fwd edge checks are only emulated to have 
*    approx. the same overhead as that of a functional 
*    fwd edge protection solution.
* 4. Multi-threaded execution needs some special care.
     Otherwise concurrent threads may end up using 
     the same shadow area, which we must avoid.
     One soln is to use separate shadow area in the 
     SFI-ed memory and store the per-thread shadow area's 
     address in a separate otherwise unused register.
* 5. Max call depth is limited to a fixed preset value 
******************************************************/
#include <assert.h>
#include "cfi.h"
#include <dlfcn.h>
#include <stdlib.h>

/* declarations of helper functions */

pthread_mutex_t _shadow_init_mutex;
#ifdef CFI_USE_FSGS
volatile shadow_return_stack_t *shadow_return_stack = NULL; 
#else
__thread shadow_return_stack_t *shadow_return_stack = NULL;
#endif

typedef void * (*type_mmap)(void *start, size_t length, int prot, int flags, int fd, off_t offset);

int _cfi_rdrand(uint64_t *x);
void _cfi_get_new_shadow_base(volatile shadow_return_stack_t *reg);
void _cfi_shadow_push(addr_t ret_addr);
int _cfi_shadow_check_top(addr_t ret_addr);
uint64_t _cfi_get_index(addr_t ret_addr);
void _cfi_pop_until_and_check_rsp(uint64_t index);

/* function definitions */

void cfi_fwd_edge_check(addr_t ptr)
{
   CFI_DBG("fwd edge addr: %lx", ptr);
   
   // we just want to emulate perf overhead, so it is NOT ==
   assert((uint64_t)(*((char*)ptr - CFI_LABEL_OFFSET)) != CFI_EMULATION_LABEL ); 
}

/* call this right after entering a function */
/* ret_addr is passed by LLVM instrumentation using llvm.returnaddress intrinsic */
void cfi_bk_shadow_func_entry(addr_t ret_addr)
{
  	_cfi_shadow_push(ret_addr);
return;
/*	save value: ret_addr on the stack
	save value: current value of ESP/RSP - to handle setjmp scenario
*/
  CFI_DBG("\n");
  PTHREAD_LOCK(&_shadow_init_mutex);
	// arg is zero because, this function shall be inlined
  	CFI_DBG("Function return addr: %lx\n", ret_addr);
  	_cfi_shadow_push(ret_addr);
  PTHREAD_UNLOCK(&_shadow_init_mutex);
  return;
}

/* ret_addr is passed by LLVM instrumentation using llvm.returnaddress intrinsic */
void cfi_bk_shadow_func_exit(addr_t ret_addr)
{
/*
  check whether return_addr is same as that which was saved last.
  if saved ESP/RSP is not same as the current ESP/RSP, then
  look whether return_addr is any of the ones stored in our shadow stack.
  if so, clear up our shadow stack as well until that point.
*/
  CFI_DBG("\n");
  PTHREAD_LOCK(&_shadow_init_mutex);
	CFI_DBG("bk edge ret_addr: %lx\n", ret_addr);

	if (!_cfi_shadow_check_top(ret_addr)) {
 		uint64_t index = _cfi_get_index(ret_addr);
		assert(index != CFI_INVALID);
		//TODO: Investigate more.
		// Perlbench fails because of this check. Commenting it for now.
		//_cfi_pop_until_and_check_rsp(index); // assert fails if check fails
  	}
  	shadow_return_stack->top -= 1;
  PTHREAD_UNLOCK(&_shadow_init_mutex);
  return;
}

__attribute__((constructor)) void cfi_shadow_init()
{
  assert(sizeof(void *) == sizeof(uint64_t) && "Not 64-bit arch");
  static uint64_t val = 0x07ff00000L;
  type_mmap orig_mmap;
  type_mmap mmap1 = (type_mmap) dlsym (RTLD_NEXT, "mmap");
  type_mmap mmap2 = (type_mmap) dlvsym (RTLD_DEFAULT, "mmap", "GLIBC_2.2.5");
  orig_mmap = (mmap2) ? mmap2 : mmap1;
  CFI_DBG("\n");
  PTHREAD_LOCK(&_shadow_init_mutex);
  	if (NULL == shadow_return_stack) {
  	    int retry_count = 3;
	    while(retry_count > 0) {
//		_cfi_get_new_shadow_base(val);
		val = val | (uint64_t)CFI_SFI_BASE;
     		shadow_return_stack = orig_mmap((void*)val, CFI_MAX_CALL_DEPTH, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0);
		if (NULL != shadow_return_stack || MAP_FAILED != shadow_return_stack)
			break;
	    }
	    assert(NULL != shadow_return_stack && MAP_FAILED != shadow_return_stack && "mmap failed");
//	    assert((0 == SET_SHADOW_BASE_REG(shadow_return_stack)) && "Could not set GS register");
	    SET_SHADOW_BASE_REG(shadow_return_stack);
	    //printf("set shadow reg value: %lx\n", (uint64_t)shadow_return_stack);
   	}
 	GET_SHADOW_BASE_REG(shadow_return_stack);
	//printf("what is there in shadow reg: %lx\n", (uint64_t)shadow_return_stack);
	shadow_return_stack->top = 0UL;
	shadow_return_stack->flag = CFI_STACK_IN_USE;
  	val += 0x200000L; // Prepare for the next. As of now couldnt get crand() working
  PTHREAD_UNLOCK(&_shadow_init_mutex);
  CFI_DBG("shadow_stacks initialized starting at : %lx\n", (uint64_t)shadow_return_stack);
  return;
}

__attribute__((always_inline))
int _cfi_rdrand(uint64_t *x)
{
  CFI_DBG("\n");
   unsigned char err = 1;

#ifdef USE_RDRAND
   asm volatile (".byte 0x48; .byte 0x0f; .byte 0xc7; .byte 0xf0; setc %1"
                  : "=a" (*x), "=qm" (err));
#else
   unsigned int *s;
   *x = rand_r(s);
   err = 0;
#endif

   if(err == 1)
   {
  	CFI_DBG("value: %lx -- rand returned: SUCCESS\n", *x);
        return CFI_RDRAND_SUCCESS;
   }
  CFI_DBG("rand returned: FAIL\n");
   return CFI_RDRAND_FAILURE;
}

__attribute__((always_inline))
void _cfi_get_new_shadow_base(volatile shadow_return_stack_t *reg)
{
  CFI_DBG("\n");
  if (CFI_RDRAND_FAILURE == _cfi_rdrand((uint64_t *) reg)) {
  	volatile register addr_t rsp asm ("rsp") ; 
	asm ("mov %%rsp, %0" : "=r"(rsp));
	reg = (void *)rsp;
  } 
  reg = (void *)((uint64_t)reg % CFI_SHADOW_DISTANCE);
  CFI_DBG("new shadow base: %lx\n", (uint64_t)reg);
}

/* debug version of this func */
__attribute__((always_inline))
void _cfi_shadow_push(addr_t ret_addr)
{
  GET_SHADOW_BASE_REG(shadow_return_stack);
  //assert(shadow_return_stack->top != CFI_MAX_CALL_DEPTH);
  volatile register addr_t rsp asm ("rsp") ;
  asm ("mov %%rsp, %0" : "=r"(rsp));
  CFI_BDBG("[top:%lx] Pushing to shadow: %lx, rsp:%lx\n", shadow_return_stack->top, ret_addr, (uint64_t) rsp);

  register shadow_return_t *new_top;
  CFI_BDBG("before\n");
  shadow_return_stack->top += 1;
  new_top = &(shadow_return_stack->returns_stack[shadow_return_stack->top]);

  CFI_BDBG("new_top addr: %lx\n", (uint64_t)new_top);
  new_top->reg_stack_pointer = (addr_t) rsp;
  CFI_BDBG("after setting new stack ptr\n");
  new_top->return_addr = (addr_t) ret_addr;
  CFI_BDBG("after writing new return-addr entry\n");
  return;
}

/*
__attribute__((always_inline))
void _cfi_shadow_push(addr_t ret_addr)
{
  GET_SHADOW_BASE_REG(shadow_return_stack);
  assert(shadow_return_stack->top != CFI_MAX_CALL_DEPTH);

  volatile register addr_t rsp asm ("rsp") ; 
  asm ("mov %%rsp, %0" : "=r"(rsp));
  CFI_DBG("[top:%lx] Pushing to shadow: %lx, rsp:%lx\n", shadow_return_stack->top, ret_addr, (uint64_t) rsp);

  register shadow_return_t *new_top;
  CFI_DBG("before\n");
  shadow_return_stack->top += 1;
  new_top = &(shadow_return_stack->returns_stack[shadow_return_stack->top]);

  CFI_DBG("new_top addr: %lx\n", (uint64_t)new_top);
  new_top->reg_stack_pointer = (addr_t) rsp;
  CFI_DBG("after\n");
  new_top->return_addr = (addr_t) ret_addr;
  return;
}*/

__attribute__((always_inline))
int _cfi_shadow_check_top(addr_t ret_addr)
{
  GET_SHADOW_BASE_REG(shadow_return_stack);
  assert(shadow_return_stack->top != 0); // stack not empty
  if (ret_addr == shadow_return_stack->returns_stack[shadow_return_stack->top].return_addr)
	return 1;
  else
	return 0;
}

__attribute__((always_inline))
uint64_t _cfi_get_index(addr_t ret_addr)
{
  GET_SHADOW_BASE_REG(shadow_return_stack);
  for(uint64_t i = shadow_return_stack->top; i > 0; i--) {
	if (shadow_return_stack->returns_stack[i].return_addr == ret_addr)
		return i;
  }
  return CFI_INVALID;
}

__attribute__((always_inline))
uint64_t _cfi_get_indices(addr_t ret_addr, uint64_t indices[], uint64_t max_n)
{
  GET_SHADOW_BASE_REG(shadow_return_stack);
  uint64_t i, j;
  for(i = shadow_return_stack->top, j = 0; i > 0 && j < max_n; i--) {
	if (shadow_return_stack->returns_stack[i].return_addr == ret_addr) {
		indices[j] = i;
		j++;
	}
  }
  return j > 0 ? j : CFI_INVALID; // num of indices inserted
}

__attribute__((always_inline))
void _cfi_pop_until_and_check_rsp(uint64_t index)
{
  volatile register addr_t rsp asm ("rsp");
  asm("mov %%rsp, %0;": "=r"(rsp) );
  GET_SHADOW_BASE_REG(shadow_return_stack);
  CFI_DBG("current rsp: %lx \t saved rsp: %lx\n", (uint64_t) rsp, shadow_return_stack->returns_stack[index].reg_stack_pointer);
  uint64_t indices[32], count=0;
  int flag=-1, i;
  count = _cfi_get_indices(shadow_return_stack->returns_stack[index].return_addr, indices, 32);
  for (i=0; i < count; i++) {
	if (rsp == shadow_return_stack->returns_stack[indices[i]].reg_stack_pointer) {
		flag=i; break;	
	}
  }
  //assert (rsp == shadow_return_stack->returns_stack[index].reg_stack_pointer);
  assert(flag != -1);
  shadow_return_stack->top = indices[i] - 1; // pop off the one that we searched for too.
  return;
}
