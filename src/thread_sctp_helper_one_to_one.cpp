#include "thread_sctp_helper_one_to_one.hpp"
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

void * SCTPClientOneToOneThread(void* args) {
    printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

	tcp_client_thread_args *thrd_args = (tcp_client_thread_args *)args;
	socklen_t slen ;
	sockaddr_in	sa;
	int client_sd, client_port = 0;
	char str[INET_ADDRSTRLEN];


	int sd = thrd_args->server_sd;

	for (;;)	{
		slen = sizeof(sockaddr_in);
		pthread_mutex_lock (&sd_mutex);
		client_sd = accept(sd, (struct sockaddr *)&sa,	&slen);
		pthread_mutex_unlock(&sd_mutex);

		if ((client_sd < 0) && (errno != EAGAIN)){
      		perror("ClientThread(): accept () failed");
			continue ;
		}

		if ((client_sd < 0) && (errno == EAGAIN))		{
			#ifdef DEBUG
				std::cout << "Waiting for connections..." << std::endl;
			#endif

			continue ;
		}

		inet_ntop(AF_INET, &(sa.sin_addr), str, INET_ADDRSTRLEN);
 	 	client_port = ntohs(sa.sin_port);

		std::cout << "TID " << (unsigned long)pthread_self() << " Client connected from " << str << " and port " << client_port <<  std::endl;

		ProcessSCTPClientWithClientSocket (client_sd);

		close(client_sd);
	}

	printf("CLIENT TID %lu\t: Something funny happened, we should not be here\n", (unsigned long)pthread_self());
	return((void*)NULL);
}
