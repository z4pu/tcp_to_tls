#include "thread_dtls_helper.hpp"
#include "thread_udp_helper.hpp"

#include "thread_helper.hpp"
#include "server_dtls_helper.hpp"
#include "server_udp_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

extern "C" {
    #include "pthread_wrap.h"
}


#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <algorithm>

extern "C" {
    #include <unistd.h>
    #include <signal.h>
}



void * DTLSSignalHandler(void * arg)
{
  (void)arg;
    sigset_t mask;
    int sig;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
    //struct itimerval timer_ping;
	printf("Signal TID %lu\n", (unsigned long)pthread_self());

    while (1) {
        sigfillset(&mask);
        sigwait(&mask, &sig);

        switch (sig) {
            case SIGTERM:
            case SIGINT:
            case SIGQUIT:
                printf("\nReceived signal %d, exiting Signal TID %lu...\n", sig, (unsigned long)pthread_self());
                server_on = false;
                return ((void*)NULL);
			default:
                break;
        }
    }
		return ((void*)NULL);
}


void * DTLSClientThread(void * args) {
    if (!server_on) return ((void*)NULL);
    printf("\nCLIENT TID %lu\n", (unsigned long)pthread_self());

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);
    struct dtls_client_thread_args *thrd_args = (struct dtls_client_thread_args *)args;

    sockaddr_in client_addr, server_addr;
    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    SSL *ssl = thrd_args->ssl;
    memcpy(&client_addr, &thrd_args->client_addr, sizeof(sockaddr_in));
    memcpy(&server_addr, &thrd_args->server_addr, sizeof(sockaddr_in));
    const int on = 1;
    int r = 0;
    long long_r = 0;
    struct timeval timeout;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};

    int client_fd = 0;

    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (client_fd < 0) {
		perror("DTLSClientThread(): socket");
		goto cleanup;
	}
    #ifdef DEBUG
    std::cout <<"New client fd is " << client_fd <<  std::endl;
    #endif
    setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

    r = bind(client_fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
    if (r == -1) {
		perror("DTLSClientThread(): bind");
		goto cleanup;
	}
    #ifdef DEBUG
    std::cout<<"Bind new client fd to server address returned " << r <<  std::endl;
    #endif

    r = connect(client_fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in));
    if (r == -1) {
		perror("DTLSClientThread(): connect");
		goto cleanup;
	}
    #ifdef DEBUG
    std::cout<<"Connect new client fd to client address returned " << r <<  std::endl;
    #endif

    /* Set new fd and set BIO to connected */
	BIO_set_fd(SSL_get_rbio(ssl), client_fd, BIO_NOCLOSE);
	long_r = BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr);

    std::cout << "BIO_CTRL_DGRAM_SET_CONNECTED returned " << long_r << std::endl;

	/* Finish handshake */
	do { r = SSL_accept(ssl); }
	while (r == 0 && server_on);
	if (r < 0 || (!server_on)) {
        OSSLErrorHandler("DTLSClientThread(): SSL_accept");
		goto cleanup;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	long_r = BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    std::cout << "BIO_CTRL_DGRAM_SET_RECV_TIMEOUT returned " << long_r << std::endl;


    r = ReceiveMessageTLS(ssl, buff);
    if (r == -1) {
        perror("DTLSClientThread():  ReceiveMessageTLS()");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("DTLSClientThread(): SendStringSize(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("DTLSClientThread(): SendString(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    #ifdef DEBUG
        std::cout <<  "--> DTLSClientThread(): OK, reversed string: "
        << buff << std::endl;
    #endif

    cleanup:
        if (client_fd)close(client_fd);
        if (SSL_get_rbio(ssl)) BIO_free(SSL_get_rbio(ssl));
        printf("Thread %lu done, connection closed.\n", (long) pthread_self());
    return ((void*)NULL);
}
