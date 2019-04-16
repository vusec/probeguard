#ifndef _UTIL_TIME_H
#define _UTIL_TIME_H

#include "util_def.h"
#include "bsd_time.h"

#include <time.h>
#include <sys/time.h>
#include <sched.h>

/* struct timeval functions. */
static inline unsigned long util_time_tv_ms(struct timeval *tv)
{
    unsigned long ms = ((tv->tv_sec) * 1000 + tv->tv_usec/1000);
    return ms;
}

static inline void util_time_tv_read(struct timeval *tv)
{
    gettimeofday(tv, NULL);
}

#define _UTIL_TIME_TV_BLOCK(B,F) do { \
        struct timeval _UTIL_TIME_TV_START, _UTIL_TIME_TV_END, _UTIL_TIME_TV_DIFF; \
        util_time_tv_read(&_UTIL_TIME_TV_START); \
        B \
        util_time_tv_read(&_UTIL_TIME_TV_END); \
        timersub(&_UTIL_TIME_TV_END, &_UTIL_TIME_TV_START, &_UTIL_TIME_TV_DIFF); \
        F \
    } while(0)

/* struct timespec functions. */
static inline unsigned long util_time_ts_to_us(struct timespec *ts)
{
    unsigned long us = ((ts->tv_sec) * 1000000 + ts->tv_nsec/1000);
    return us;
}

static __attribute__((always_inline,used)) void util_time_ts_read(struct timespec *ts)
{
#ifdef CLOCK_MONOTONIC_RAW
    clock_gettime(CLOCK_MONOTONIC_RAW, ts);
#else
    clock_gettime(CLOCK_MONOTONIC, ts);
#endif
}

#define _UTIL_TIME_TS_BLOCK(B,F) do { \
        struct timespec _UTIL_TIME_TS_START, _UTIL_TIME_TS_END, _UTIL_TIME_TS_DIFF; \
        util_time_ts_read(&_UTIL_TIME_TS_START); \
        B \
        util_time_ts_read(&_UTIL_TIME_TS_END); \
        timespecsub(&_UTIL_TIME_TS_END, &_UTIL_TIME_TS_START, &_UTIL_TIME_TS_DIFF); \
        F \
    } while(0)

/* timestamp counter functions. */
#if defined(__i386__)

static __attribute__((always_inline,used)) unsigned long long util_time_tsc_read()
{
    unsigned long long x;
    __asm__ volatile ("rdtsc" : "=A" (x) );
    return x;
}

#elif defined(__x86_64__)

static __attribute__((always_inline,used)) unsigned long long util_time_tsc_read()
{
    unsigned long long hi, lo;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#else

#error "Platform not supported for high performance time measurement using the RDTSC instruction!"

#endif

static __attribute__((always_inline,used)) unsigned long long util_time_tsc_read_ns(
    double cycles_per_ns)
{
    return (double)util_time_tsc_read()/cycles_per_ns;
}

static __attribute__((always_inline,used)) double util_time_get_cycles_per_ns(int set_affinity)
{
    cpu_set_t cpu_mask;
    double cycles_per_ns;
    unsigned long long i, start, end, diff;

    /* Bind to the first CPU to get stable measurements. */
    if (set_affinity) {
        CPU_ZERO(&cpu_mask);
        CPU_SET(0, &cpu_mask);
        sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);
    }

    /* Compute the number of cycles per ns. */
    _UTIL_TIME_TS_BLOCK(
        start = util_time_tsc_read();
        for (i = 0; i < 1000000; i++);
        end = util_time_tsc_read();
    ,
        diff = _UTIL_TIME_TS_DIFF.tv_sec*1000000000+_UTIL_TIME_TS_DIFF.tv_nsec;
    );
    cycles_per_ns = (double)(end - start)/(double)(diff ? diff : 1);
    if (cycles_per_ns == 0) {
        cycles_per_ns = 1;
    }
    return cycles_per_ns;
}

#endif /* _UTIL_TIME_H */
