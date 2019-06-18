#include "thread_sctp_helper_one_to_many.hpp"
#include "thread_helper.hpp"
#include "server_tcp_helper.hpp"
#include "server_sctp_helper_one_to_one.hpp"
#include "server_sctp_helper_one_to_many.hpp"

extern "C" {
    #include "pthread_wrap.h"
}

#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <unistd.h>
}


void * SCTPClientOneToManyThread(void* args) {
    printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

    udp_client_thread_args *thrd_args = (udp_client_thread_args *)args;

    int server_sd = thrd_args->server_sd;

    for (;;)	{
        pthread_mutex_lock (&sd_mutex);
        ProcessSCTPClientWithServerSocket (server_sd);
        std::cout << "Ending for() loop for ";
        printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
        pthread_mutex_unlock(&sd_mutex);

    }

    printf("CLIENT TID %lu\t: Something funny happened, we should not be here\n", (unsigned long)pthread_self());
    return((void*)NULL);
}
