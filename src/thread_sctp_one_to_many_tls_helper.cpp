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

    struct sctp_one_to_many_client_thread_args *thrd_args = (struct sctp_one_to_many_client_thread_args *)args;
    int peer_assoc_id, server_sd, r = 0;
    sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    unsigned char buff[MAX_STRING_LENGTH+1] = {};


    SSL * ssl = thrd_args->ssl;
    server_sd =  thrd_args->server_sd;
    peer_assoc_id = thrd_args->peer_assoc_id;
    memcpy(&client_addr, &thrd_args->client_addr, sizeof(sockaddr_in));

    std::cout << "Server sd: " << server_sd << std::endl;
    std::cout << "Association ID: " << peer_assoc_id << std::endl;


    // waits for a TLS/SSL client to initiate the TLS/SSL handshake
    rwlock_wrlock(&ssl_lock);
    r = SSL_accept(ssl);
    rwlock_unlock(&ssl_lock);
    if (r <= 0) {
         SSLReadWriteErrorHandler(ssl, r);
         goto cleanup;
    }

    std::cout << "SSL Handshake OK, returned " << r << std::endl;
    rwlock_rdlock(&ssl_lock);
    r = ReceiveMessageTLS(ssl, buff);
    rwlock_unlock(&ssl_lock);
    if (r == -1) {
        perror("ProcessTLSClient(): ReceiveMessageTLS()");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    rwlock_wrlock(&ssl_lock);
    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    rwlock_unlock(&ssl_lock);
    if (r == -1) {
        perror("ProcessTLSClient(): SendStringSize(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    rwlock_wrlock(&ssl_lock);
    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    rwlock_unlock(&ssl_lock);
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
    if(ssl) SSL_free(ssl);
    printf("Thread %lu done, connection closed.\n", (long) pthread_self());
    return ((void*)NULL);
}
