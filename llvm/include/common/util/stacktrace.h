#ifndef _UTIL_STACKTRACE_H
#define _UTIL_STACKTRACE_H

#include "util_def.h"

#include <execinfo.h>
#include <stdio.h>
#include <ucontext.h>

#include "string.h"

/*
 * Signal handling code from:
 *  - http://www.linuxjournal.com/article/6391
 */

/* get REG_EIP / REG_RIP from ucontext.h */
#ifndef EIP
#define EIP     14
#endif

#if (defined (__x86_64__))
#    ifndef REG_RIP
#        define REG_RIP REG_INDEX(rip) /* seems to be 16 */
#    endif
#endif

typedef int (*printf_t)(const char *fmt, ...);

static __attribute__((always_inline, used))
void util_stacktrace_print_gen(void *override_trace_ptr,
    unsigned override_trace_index, const char *fmt,
    printf_t custom_printf)
{
    void *array[100];
    size_t size;
    char **strings;
    size_t i;

    size = backtrace(array, 100);
    if (override_trace_ptr && override_trace_index < size) {
        array[override_trace_index] = override_trace_ptr;
    }
    strings = backtrace_symbols(array, size);

    for (i = 0; i < size; i++)
        if (!custom_printf)
           _UTIL_PRINTF(fmt, strings[i]);
        else
            custom_printf(fmt, strings[i]);

    free (strings);
}

static __attribute__((always_inline, used)) void util_stacktrace_print(void)
{
    util_stacktrace_print_gen(NULL, 0, "%s\n", NULL);
}

static __attribute__((always_inline, used)) void util_stacktrace_print_custom(
    printf_t custom_printf)
{
    util_stacktrace_print_gen(NULL, 0, "%s\n", custom_printf);
}

static __attribute__((always_inline, used))
unsigned long util_stacktrace_hash_gen(int stacktrace_depth, int skipped_frames, char *skip_function_name)
{
    void *array[stacktrace_depth];
    size_t size, i;
    int offset;
    char **strings;
    unsigned long hash = 0;

    size = backtrace(array, stacktrace_depth);
    strings = backtrace_symbols(array, size);

    if (strings != NULL) {

        if (skip_function_name) {
            for (i = skipped_frames ; i < size ; i++)
                if (strstr(strings[i], skip_function_name))
                    skipped_frames = i + 1;
        }

        /* Exclude the return address from the hash to make it invariant with respect to address space randomization. */
        for (i = skipped_frames ; i < size ; i++) {
            offset = strlen(strings[i]) - 1;
            while ((offset >= 0) && (strings[i][offset] != ' ')) {
                offset--;
            }
            if (offset >= 0) {
                strings[i][offset] = '\0';
            }
            while ((offset >= 0) && (strings[i][offset] != ' ')) {
                offset--;
            }
            if (offset <= 0) {
                offset = 0;
            }
            else {
                offset++;
            }
            hash = util_strhash(hash, &strings[i][offset]);
        }

        free(strings);
    }

    return hash;
}

static __attribute__((always_inline, used)) unsigned long util_stacktrace_hash(void)
{
    return util_stacktrace_hash_gen(100, 0, NULL);
}

static __attribute__((always_inline, used)) unsigned long util_stacktrace_hash_skip(char *skip_function_name)
{
    return util_stacktrace_hash_gen(100, 0, skip_function_name);
}

static inline void *util_stacktrace_uc_to_eip(ucontext_t *uc)
{
    void *pnt = NULL;;

#if defined(__x86_64__)
    pnt = (void*) uc->uc_mcontext.gregs[REG_RIP] ;
#elif defined(__hppa__)
    pnt = (void*) uc->uc_mcontext.sc_iaoq[0] & ~0×3UL ;
#elif (defined (__ppc__)) || (defined (__powerpc__))
    pnt = (void*) uc->uc_mcontext.regs->nip ;
#elif defined(__sparc__)
    struct sigcontext* sc = (struct sigcontext*) secret;
    #if __WORDSIZE == 64
        pnt = (void*) scp->sigc_regs.tpc ;
    #else
        pnt = (void*) scp->si_regs.pc ;
    #endif
#elif defined(__i386__)
#ifdef __MINIX
    pnt = (void*) uc->uc_mcontext.__gregs[_REG_EIP];
#else
    pnt = (void*) uc->uc_mcontext.gregs[REG_EIP] ;
#endif
#else
#    error "Arch not supported!"

/* potentially correct for other archs:
 * alpha: ucp->m_context.sc_pc
 * arm: ucp->m_context.ctx.arm_pc
 * ia64: ucp->m_context.sc_ip & ~0×3UL
 * mips: ucp->m_context.sc_pc
 * s390: ucp->m_context.sregs->regs.psw.addr
*/
#endif

    return pnt;
}

static __attribute__((always_inline, used))
void util_stacktrace_print_sig_handler(int signum, siginfo_t *info,
    ucontext_t *uc, unsigned caller_offset)
{
    void *override_trace_ptr;
    unsigned override_trace_index;
    void *eip = util_stacktrace_uc_to_eip(uc);

    _UTIL_PRINTF("\n");
    if (signum == SIGSEGV) {
        _UTIL_PRINTF("Faulty address is %p, called from %p\n",
            info->si_addr, eip);
    }

    /* The first two entries in the stack frame chain when you
     * get into the signal handler contain, respectively, a
     * return address inside your signal handler and one inside
     * sigaction() in libc. The stack frame of the last function
     * called before the signal (which, in case of fault signals,
     * also is the one that supposedly caused the problem) is lost.
    */

    /* the third parameter to the signal handler points to an
     * ucontext_t structure that contains the values of the CPU
     * registers when the signal was raised.
     */

    /* overwrite sigaction with caller's address */
    override_trace_ptr = eip;
    override_trace_index = caller_offset;

    util_stacktrace_print_gen(override_trace_ptr,
        override_trace_index, "%s\n", NULL);
}

#endif /* _UTIL_STACKTRACE_H */
