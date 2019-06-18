#ifndef THREAD_SCTP_ONE_TO_MANY_TLS_HELPER_HPP
#define THREAD_SCTP_ONE_TO_MANY_TLS_HELPER_HPP

#include <pthread.h>

extern pthread_mutex_t ssl_lock;

void * SCTPTLSOneToManyClientThread(void* args);

#endif /* THREAD_SCTP_ONE_TO_MANY_TLS_HELPER_HPP */
