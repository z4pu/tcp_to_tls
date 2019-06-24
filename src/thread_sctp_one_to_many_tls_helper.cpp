#include "thread_sctp_helper_one_to_many.hpp"
#include "thread_sctp_one_to_many_tls_helper.hpp"
#include "thread_helper.hpp"
#include "thread_tls_helper.hpp"
#include "server_udp_helper.hpp"
#include "server_sctp_helper_one_to_many.hpp"
#include "common.hpp"
#include "common_tls.hpp"

extern "C" {
    #include "pthread_wrap.h"
}

#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <unistd.h>
    #include <netinet/sctp.h>
}

void * SCTPTLSOneToManyClientThread(void* args) {
    printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

    struct sctp_prim peer_addr;
    struct sctp_one_to_many_client_thread_args *thrd_args = (struct sctp_one_to_many_client_thread_args *)args;

    sockaddr_in cookie_client_addr;
    memset(&peer_addr, 0, sizeof(struct sctp_prim));
    memset(&cookie_client_addr, 0, sizeof(struct sockaddr_in));
    socklen_t address_len = sizeof(struct sockaddr_in);

    SSL_CTX *ctx = thrd_args->ctx;
    SSL * ssl = thrd_args->ssl;
    int server_sd =  thrd_args->server_sd;
    sctp_assoc_t    sstat_assoc_id = thrd_args->sstat_assoc_id;
    memcpy(&cookie_client_addr, &thrd_args->client_addr, sizeof(sockaddr_in));

    int r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    int client_fd = 0;

    std::cout << "Server sd: " << server_sd << std::endl;

    // Set the peer in this thread
    peer_addr.ssp_assoc_id = sstat_assoc_id;
    memcpy(&peer_addr.ssp_addr, (sockaddr *)&cookie_client_addr, sizeof(struct sockaddr_in));

    r = setsockopt(server_sd, IPPROTO_SCTP, SCTP_PRIMARY_ADDR,
             &peer_addr, sizeof(struct sctp_prim));
	if (r < 0) {
		perror("SCTPTLSOneToManyClientThread(): setsockopt(SCTP_PRIMARY_ADDR)");
		goto cleanup;
	}


    // waits for a TLS/SSL client to initiate the TLS/SSL handshake
    if (SSL_accept(ssl) <= 0) {
         OSSLErrorHandler("SSL_accept()");
         goto cleanup;
    }
    r = ReceiveMessageTLS(ssl, buff);
    if (r == -1) {
        perror("ProcessTLSClient(): ReceiveMessageTLS()");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendStringSize(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendString(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    #ifdef DEBUG
        std::cout <<  "--> ProcessTLSClient(): OK, reversed string: "
        << buff << std::endl;
    #endif
    if (ssl) SSL_shutdown(ssl);

    cleanup:
    if(SSL_get_rbio(ssl)) BIO_free(SSL_get_rbio(ssl));
    if(ssl) SSL_free(ssl);
    if (client_fd) close (client_fd);
    printf("Thread %lu done, connection closed.\n", (long) pthread_self());
    return ((void*)NULL);
}
