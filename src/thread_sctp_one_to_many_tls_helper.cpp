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
}

void * SCTPTLSOneToManyClientThread(void* args) {
    printf("CLIENT TID %lu\n", (unsigned long)pthread_self());
	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr);

    struct sctp_one_to_many_client_thread_args *thrd_args = (struct sctp_one_to_many_client_thread_args *)args;

    sockaddr_in client_addr, server_addr;
    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    SSL *ssl = thrd_args->ssl;
    SSL_CTX *ctx = thrd_args->ctx;
    memcpy(&client_addr, &thrd_args->client_addr, sizeof(sockaddr_in));
    memcpy(&server_addr, &thrd_args->server_addr, sizeof(sockaddr_in));
    const int on = 1;
    int r = 0;
    long long_r = 0;
    struct timeval timeout;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    //BIO_ADDR* client_addr_bio = (BIO_ADDR *) &client_addr;
    BIO * dgramBio = nullptr;
    int client_fd = 0;

    mutexLock(&ctx_lock);
    SSL *ssl_new = SSL_new(ctx);
    if (ssl == NULL){
        OSSLErrorHandler("main(): SSL_new(): ");
        mutexUnlock(&ctx_lock);
        goto cleanup;
    }
    mutexUnlock(&ctx_lock);


    client_fd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (client_fd < 0) {
        perror("SCTPTLSOneToManyClientThread(): socket");
        goto cleanup;
    }
    #ifdef DEBUG
    std::cout<< std::endl <<"New client fd is " << client_fd <<  std::endl;
    #endif
    setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, (const void*) &on, (socklen_t) sizeof(on));

    dgramBio = BIO_new_dgram(client_fd, BIO_NOCLOSE);
    if (!dgramBio) {
        OSSLErrorHandler("SetPeerAsSCTPDTLSEndpoint(): BIO_new_dgram(): cannot set peer fd");
        goto cleanup;
    }

    if (BIO_ctrl_dgram_connect(dgramBio, &client_addr) == 0) {
        BIO_free(dgramBio);
        goto cleanup;
    }

    SSL_set_bio(ssl_new, dgramBio, dgramBio);
    SSL_set_accept_state(ssl_new);
    // r = bind(client_fd, (const struct sockaddr *) &server_addr, sizeof(struct sockaddr_in));
    // if (r) {
    //     perror("SCTPTLSOneToManyClientThread(): bind");
    //     goto cleanup;
    // }
    // #ifdef DEBUG
    // std::cout<< std::endl <<"Bind new client fd to server address returned " << r <<  std::endl;
    // #endif

    // r = connect(client_fd, (struct sockaddr *) &client_addr, sizeof(struct sockaddr_in));
    // if (r) {
    //     perror("SCTPTLSOneToManyClientThread(): connect");
    //     goto cleanup;
    // }
    // #ifdef DEBUG
    // std::cout<< std::endl <<"Connect new client fd to client address returned " << r <<  std::endl;
    // #endif

    /* Set new fd and set BIO to connected */
    // BIO_set_fd(SSL_get_rbio(ssl), client_fd, BIO_NOCLOSE);
    // long_r = BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_CONNECT, 0, &client_addr);
    // std::cout << "BIO_CTRL_DGRAM_CONNECT returned " << long_r << std::endl;

    /* Finish handshake */
    do { r = SSL_do_handshake(ssl_new); }
    while (r == 0);
    if (r < 0) {
        OSSLErrorHandler("SCTPTLSOneToManyClientThread(): SSL_accept");
        goto cleanup;
    }

    /* Set and activate timeouts */
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    long_r = BIO_ctrl(SSL_get_rbio(ssl_new), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
    std::cout << "BIO_CTRL_DGRAM_SET_RECV_TIMEOUT returned " << long_r << std::endl;

    r = ReceiveMessageTLS(ssl_new, buff);
    if (r == -1) {
        perror("SCTPTLSOneToManyClientThread():  ReceiveMessageTLS()");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl_new, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("SCTPTLSOneToManyClientThread(): SendStringSize(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    r = SendStringTLS(ssl_new, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("SCTPTLSOneToManyClientThread(): SendString(reversed string)");
        SSL_shutdown(ssl);
        goto cleanup;
    }

    #ifdef DEBUG
        std::cout <<  "--> SCTPTLSOneToManyClientThread(): OK, reversed string: "
        << buff << std::endl;
    #endif

    cleanup:
        if (client_fd)close(client_fd);
        printf("Thread %lu done, connection closed.\n", (long) pthread_self());
    return ((void*)NULL);
}
