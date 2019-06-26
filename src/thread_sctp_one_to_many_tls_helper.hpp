#ifndef THREAD_SCTP_ONE_TO_MANY_TLS_HELPER_HPP
#define THREAD_SCTP_ONE_TO_MANY_TLS_HELPER_HPP

#include <pthread.h>

extern pthread_rwlock_t ssl_lock;
extern bool server_on;

void * SCTPTLSOneToManyClientThread(void* args);

#endif /* THREAD_SCTP_ONE_TO_MANY_TLS_HELPER_HPP */
