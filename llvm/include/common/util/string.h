#ifndef _UTIL_STRING_H
#define _UTIL_STRING_H

#include "util_def.h"

#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

static inline char* util_strsigset(const sigset_t *set)
{
    int i, first = 1;
    char *buffer = (char*) malloc(20*_NSIG);
    buffer[0] = '\0';
    for (i=1;i<_NSIG;i++) {
        if(sigismember(set, i)) {
            if (!first) {
                strcat(buffer, "|");
            }
            else {
                first = 0;
            }
            strcat(buffer, strsignal(i));
        }
    }
    return buffer;
}

static inline char* util_strwait_status(int status, char *buff)
{
    if (WIFEXITED(status)) {
        sprintf(buff, "exited, status=%d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        sprintf(buff, "killed by signal %d", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        sprintf(buff, "stopped by signal %d", WSTOPSIG(status));
#ifndef __MINIX
    } else if (WIFCONTINUED(status)) {
        sprintf(buff, "continued");
#endif
    }

    return buff;
}

static inline char* util_strflags(unsigned long flags, const char* str,
    char* buff)
{
    int i, num_flags = strlen(str);

    for (i=0;i<num_flags;i++) {
        char c = (flags & (1 << i)) ? str[i] : '-';
        buff[i] = c;
    }
    buff[i] = '\0';

    return buff;
}

static __attribute__((always_inline,used))
unsigned long util_strhash(unsigned long hash, const char *s)
{
	/* Equivalent to Java's string hashing method. */
	if (s != NULL) {
		for (; *s != '\0'; s++) {
			hash = *s + 31 * hash;
		}
	}

    return hash;
}

#endif /* _UTIL_STRING_H */
