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

    struct sctp_paddrparams peer_params;
    struct sctp_one_to_many_client_thread_args *thrd_args = (struct sctp_one_to_many_client_thread_args *)args;
    BIO * dgramBio;

    sockaddr_in cookie_client_addr;
    memset(&peer_params, 0, sizeof(struct sctp_paddrparams));
    memset(&cookie_client_addr, 0, sizeof(struct sockaddr_in));



    SSL * ssl = thrd_args->ssl;
    int server_sd =  thrd_args->server_sd;
    sctp_assoc_t  peer_assoc_id = thrd_args->peer_assoc_id;
    memcpy(&cookie_client_addr, &thrd_args->client_addr, sizeof(sockaddr_in));

    int r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};

    std::cout << "Server sd: " << server_sd << std::endl;

    mutexLock(&sd_mutex);
    dgramBio = BIO_new_dgram_sctp(server_sd, BIO_NOCLOSE);
    mutexUnlock(&sd_mutex);
    if (!dgramBio) {
        OSSLErrorHandler("main(): BIO_new_dgram_sctp(): cannot create from fd");
        goto cleanup;
    }
    SSL_set_bio(ssl, dgramBio, dgramBio);
    SSL_set_accept_state(ssl);

    // waits for a TLS/SSL client to initiate the TLS/SSL handshake
    r = SSL_accept(ssl);
    if (r <= 0) {
         SSLReadWriteErrorHandler(ssl, r);
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
    printf("Thread %lu done, connection closed.\n", (long) pthread_self());
    return ((void*)NULL);
}
