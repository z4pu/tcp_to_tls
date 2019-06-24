#include "thread_udp_helper.hpp"
#include "thread_helper.hpp"
#include "server_udp_helper.hpp"

extern "C" {
    #include "pthread_wrap.h"
}

#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <unistd.h>
}

void * UDPClientThread(void* args) {
    printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

	udp_client_thread_args *thrd_args = (udp_client_thread_args *)args;
	int r = 0;

	int server_sd = thrd_args->server_sd;

    for (;;)	{
		r = ProcessUDPClient (server_sd);
        if (r == -1) {
            printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
            perror("ProcessUDPClient(): error");
        }
        std::cout << "Ending for() loop for ";
        printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
	}

	printf("CLIENT TID %lu\t: Something funny happened, we should not be here\n", (unsigned long)pthread_self());
	return((void*)NULL);
}
