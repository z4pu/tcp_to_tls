#include "thread_tcp_helper.hpp"
#include "thread_tls_helper.hpp"
#include "thread_helper.hpp"
#include "server_tls_helper.hpp"
#include "server_tcp_helper.hpp"
#include "common_tls.hpp"

extern "C" {
    #include "pthread_wrap.h"
}

#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <unistd.h>
}

void * TLSClientThread(void* args) {
    printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

	tls_client_thread_args *thrd_args = (tls_client_thread_args *)args;
	socklen_t slen ;
	sockaddr_in	sa;
	int client_sd, client_port = 0;
	char str[INET_ADDRSTRLEN];
    SSL_CTX* ctx = nullptr;


	int sd = thrd_args->server_sd;
    ctx = thrd_args->ctx;

	for (;;)	{
		slen = sizeof(sockaddr_in);
		pthread_mutex_lock (&sd_mutex);
		client_sd = accept(sd, (struct sockaddr *)&sa,	&slen);
		pthread_mutex_unlock(&sd_mutex);

		if ((client_sd < 0) && (errno != EAGAIN)){
      		perror("TLSClientThread(): accept () failed");
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

		HandleTLSClientInThread (client_sd, ctx);

		close(client_sd);
	}

	printf("CLIENT TID %lu\t: Something funny happened, we should not be here\n", (unsigned long)pthread_self());
	return((void*)NULL);
}

/**
* @brief Initialise global pthread_mutex_t *crypto_mutexes for OpenSSL threading
* @param [in] nothing
* @return nothing
*/

void setup_openssl_thread_support(void)
{
	int i, n;
	n = CRYPTO_num_locks();

	crypto_mutexes = (pthread_mutex_t*)(malloc(sizeof(pthread_mutex_t)*n));
	if (crypto_mutexes == NULL){
		OSSLErrorHandler("setup_openssl_thread_support(): Cannot allocate crypto_mutexes");
		exit(EXIT_FAILURE);
	}
	for (i = 0; i < n; i++) {
			mutexInit(&crypto_mutexes[i], NULL);
	}
	CRYPTO_THREADID_set_callback(thread_id);
	CRYPTO_set_locking_callback(openssl_locking_function);
}

void HandleTLSClientInThread(const int& client_sd, SSL_CTX * ctx) {

    SSL *ssl = nullptr;

    if (!client_sd){
		std::cerr << "HandleTLSClient(): invalid socket descriptor" << std::endl;
		return;
	}

    mutexLock(&ctx_lock);
    ssl = SSL_new(ctx);
    if (ssl == NULL){
        OSSLErrorHandler("SSL_new(): Error creating new SSL from ctx");
        mutexUnlock(&ctx_lock);
        return;
    }
    mutexUnlock(&ctx_lock);

    SSL_set_fd(ssl, client_sd);

  	if (SSL_accept(ssl) <= 0) {
      	OSSLErrorHandler("HandleOpenSSLClient(): SSL_accept()");
		return;
  	}

    std::cout << "\nClient accepted on SSL\n";

    ProcessTLSClient(ssl);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_sd);
    return;
}
