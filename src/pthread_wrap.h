/*
 * Pthread wrapper functions
 *
 * Copyright (C) 2008-2009 Florent Bondoux
 *
 * This file is part of Campagnol.
 *
 * Campagnol is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Campagnol is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Campagnol.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 *
 */

#ifndef PTHREAD_WRAP_H_
#define PTHREAD_WRAP_H_

/*
 * Wrapper functions around a few pthread functions
 * These functions exit in case of error
 */

//#include "config.h"
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/time.h>
#include <stdlib.h>
//#include "log.h"

static inline void mutexInit(pthread_mutex_t *mutex, pthread_mutexattr_t *attrs);
static inline void mutexDestroy(pthread_mutex_t *mutex);
static inline int mutexLock(pthread_mutex_t *mutex);
static inline int mutexUnlock(pthread_mutex_t *mutex);

static inline void mutexattrInit(pthread_mutexattr_t *attrs);
static inline void mutexattrDestroy(pthread_mutexattr_t *attrs);
static inline void mutexattrSettype(pthread_mutexattr_t *attrs, int type);

static inline void rwlock_init(pthread_rwlock_t *lock);
static inline void rwlock_destroy(pthread_rwlock_t *lock);
static inline int rwlock_rdlock(pthread_rwlock_t *lock);
static inline int rwlock_wrlock(pthread_rwlock_t *lock);
static inline int rwlock_unlock(pthread_rwlock_t *lock);

static inline void conditionInit(pthread_cond_t *cond, pthread_condattr_t *attrs);
static inline void conditionDestroy(pthread_cond_t *cond);
static inline int conditionWait(pthread_cond_t *cond, pthread_mutex_t *mutex);
static inline int conditionTimedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abs_timeout);
static inline int conditionBroadcast(pthread_cond_t *cond);
static inline int conditionSignal(pthread_cond_t *cond);

static inline pthread_t createThread(void * (*start_routine)(void *), void * arg);
static inline pthread_t createDetachedThread(void * (*start_routine)(void *), void * arg);
static inline void joinThread(pthread_t thread, void **value_ptr);
static inline void makeTimeOut (struct timespec *tsp, unsigned long seconds);


void mutexInit(pthread_mutex_t *mutex, pthread_mutexattr_t *attrs) {
    assert(mutex);
    int r = pthread_mutex_init(mutex, attrs);
    if (r != 0) {
        perror("Error pthread_mutex_init()");
        abort();
    }
}

void mutexDestroy(pthread_mutex_t *mutex) {
    assert(mutex);
    int r = pthread_mutex_destroy(mutex);
    if (r != 0) {
        perror("Error pthread_mutex_destroy()");
        abort();
    }
}

int mutexLock(pthread_mutex_t *mutex) {
    assert(mutex);
    int r = pthread_mutex_lock(mutex);
    if (r != 0) {
        perror("Error pthread_mutex_lock()");
        return -1;
    }
    return 0;
}

int mutexUnlock(pthread_mutex_t *mutex) {
    assert(mutex);
    int r = pthread_mutex_unlock(mutex);
    if (r != 0) {
        perror("Error pthread_mutex_unlock()");
        return -1;
    }
    return 0;
}

void mutexattrInit(pthread_mutexattr_t *attrs) {
    assert(attrs);
    int r = pthread_mutexattr_init(attrs);
    if (r != 0) {
        perror("Error pthread_mutexattr_init()");
        abort();
    }
}

void mutexattrSettype(pthread_mutexattr_t *attrs, int type) {
    assert(attrs);
    int r = pthread_mutexattr_settype(attrs, type);
    if (r != 0) {
        perror("Error pthread_mutexattr_settype()");
        abort();
    }
}

void mutexattrDestroy(pthread_mutexattr_t *attrs) {
    assert(attrs);
    int r = pthread_mutexattr_destroy(attrs);
    if (r != 0) {
        perror("Error pthread_mutexattr_destroy()");
        abort();
    }
}
void rwlock_init(pthread_rwlock_t *lock){
	if (pthread_rwlock_init(lock, NULL) != 0){
		perror("Err rwlock_init");
    abort();
  }
}

void rwlock_destroy(pthread_rwlock_t *lock){
		int r = pthread_rwlock_destroy(lock);
		if (r != 0) {
				perror("Error rwlock_destroy()");
        abort();
		}
}
int rwlock_rdlock(pthread_rwlock_t *lock){
		int r = pthread_rwlock_rdlock(lock);
		if (r != 0) {
				perror("Error rwlock_rdlock()");
        return -1;
		}
    return 0;
}

int rwlock_wrlock(pthread_rwlock_t *lock){
		int r = pthread_rwlock_wrlock(lock);
		if (r != 0) {
				perror("Error rwlock_wrlock()");
        return -1;
		}
    return 0;
}

int rwlock_unlock(pthread_rwlock_t *lock){
		int r = pthread_rwlock_unlock(lock);
		if (r != 0) {
				perror("Error pthread_rwlock_unlock()");
        return -1;
		}
    return 0;
}

void conditionInit(pthread_cond_t *cond, pthread_condattr_t *attrs) {
    assert(cond);
    int r = pthread_cond_init(cond, attrs);
    if (r != 0) {
        perror("Error pthread_cond_init()");
        abort();
    }
}

void conditionDestroy(pthread_cond_t *cond) {
    assert(cond);
    int r = pthread_cond_destroy(cond);
    if (r != 0) {
        perror("Error pthread_cond_destroy()");
        abort();
    }
}

int conditionWait(pthread_cond_t *cond, pthread_mutex_t *mutex) {
    assert(cond);
    int retval;
    retval = pthread_cond_wait(cond, mutex);
    if (retval != 0) {
        perror("Error pthread_cond_wait()");
        return (-1);
    }
    return retval;
}

int conditionTimedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
        const struct timespec *abs_timeout) {
    assert(cond);
    assert(abs_timeout);
    int retval;
    retval = pthread_cond_timedwait(cond, mutex, abs_timeout);
    if (retval != 0 && retval != ETIMEDOUT) {
        perror("Error pthread_cond_timedwait()");
        return (-1);
    }
    return retval;
}

int conditionBroadcast(pthread_cond_t *cond) {
    assert(cond);
    int retval;
    retval = pthread_cond_broadcast(cond);
    if (retval != 0) {
        perror("Error pthread_cond_broadcast()");
        abort();
    }
    return retval;
}

int conditionSignal(pthread_cond_t *cond) {
    assert(cond);
    int retval;
    retval = pthread_cond_signal(cond);
    if (retval != 0) {
        perror("Error pthread_cond_signal()");
        abort();
    }
    return retval;
}

/*
 * Create a thread executing start_routine with the arguments arg
 * without attributes
 */
pthread_t createThread(void * (*start_routine)(void *), void * arg) {
    assert(start_routine);
    int retval;
    pthread_t thread;
    retval = pthread_create(&thread, NULL, start_routine, arg);
    if (retval != 0) {
        perror("Error pthread_create()");
        abort();
    }
    return thread;
}

/*
 * Create a thread executing start_routine with the arguments arg
 * without attributes. Then call pthread_detach.
 */
pthread_t createDetachedThread(void * (*start_routine)(void *), void * arg) {
    int retval;
    pthread_t thread = createThread(start_routine, arg);
    retval = pthread_detach(thread);
    if (retval != 0) {
        perror("Error pthread_detach()");
        abort();
    }
    return thread;
}

void joinThread(pthread_t thread, void **value_ptr) {
    int r = pthread_join(thread, value_ptr);
    if (r != 0) {
        perror("Error pthread_join()");
        printf("Thread exit code %d\n", *((int*)value_ptr));
    }
}

void makeTimeOut (struct timespec *tsp, unsigned long seconds)
{
  struct timeval now;
  /* get the current time */
  gettimeofday(&now, NULL);
  tsp->tv_sec = now.tv_sec;
  tsp->tv_nsec = now.tv_usec * 1000; /* usec to nsec */
  /* add the offset to get timeout value */
  tsp->tv_sec += seconds;
}

#endif /*PTHREAD_WRAP_H_*/
