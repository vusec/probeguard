#ifndef _UTIL_COND_VAR_H
#define _UTIL_COND_VAR_H

#include "util_def.h"

#include <pthread.h>

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int var;
} util_cond_var_t;

static inline void util_cond_var_init(util_cond_var_t *cond_var, int value,
    int is_pshared)
{
    pthread_mutexattr_t attr;
    pthread_condattr_t cattr;
    int ret;

    ret = pthread_mutexattr_init(&attr);
    assert(ret == 0);
    if (is_pshared) {
        ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        assert(ret == 0);
    }
    ret = pthread_mutex_init(&cond_var->mutex, &attr);
    assert(ret == 0);
    ret = pthread_mutexattr_destroy(&attr);
    assert(ret == 0);
    ret = pthread_condattr_init(&cattr);
    assert(ret == 0);
    if (is_pshared) {
        ret = pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
        assert(ret == 0);
    }
    ret = pthread_cond_init(&cond_var->cond, &cattr);
    assert(ret == 0);
    ret = pthread_condattr_destroy(&cattr);
    assert(ret == 0);
    cond_var->var = value;
}

static inline void util_cond_var_wait_locked(util_cond_var_t *cond_var, int value)
{
    /* The caller must hold the cond_var->mutex. */
    while(cond_var->var != value) {
        pthread_cond_wait(&cond_var->cond, &cond_var->mutex);
    }
    pthread_mutex_unlock(&cond_var->mutex);
}

static inline void util_cond_var_wait(util_cond_var_t *cond_var, int value)
{
    pthread_mutex_lock(&cond_var->mutex);
    util_cond_var_wait_locked(cond_var, value);
}

static inline int util_cond_var_timedwait(util_cond_var_t *cond_var,
    int value, struct timespec *ts)
{
    int ret = 0;

    pthread_mutex_lock(&cond_var->mutex);
    while(cond_var->var != value) {
        ret = pthread_cond_timedwait(&cond_var->cond, &cond_var->mutex, ts);
        if (ret == ETIMEDOUT) {
            break;
        }
    }
    pthread_mutex_unlock(&cond_var->mutex);

    return ret;
}

static inline void util_cond_var_signal(util_cond_var_t *cond_var, int value)
{
    pthread_mutex_lock(&cond_var->mutex);
    cond_var->var = value;
    pthread_cond_signal(&cond_var->cond);
    pthread_mutex_unlock(&cond_var->mutex);
}

static inline void util_cond_var_broadcast(util_cond_var_t *cond_var, int value)
{
    pthread_mutex_lock(&cond_var->mutex);
    cond_var->var = value;
    pthread_cond_broadcast(&cond_var->cond);
    pthread_mutex_unlock(&cond_var->mutex);
}

static inline void util_cond_var_destroy(util_cond_var_t *cond_var)
{
    pthread_mutex_destroy(&cond_var->mutex);
    pthread_cond_destroy(&cond_var->cond);
    cond_var->var = 0;
}

#endif /* _UTIL_COND_VAR_H */
