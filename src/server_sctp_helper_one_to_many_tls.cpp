#include "server_sctp_helper_one_to_many_tls.hpp"
#include "common.hpp"
#include "common_tls.hpp"
#include "common_sctp.hpp"

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
}

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

extern "C" {
    #include <unistd.h>
}

#include <iostream>
#include <string>

void ProcessSCTPTLSClientWithServerSocket (const int& server_sd, SSL_CTX* const ctx)
{
    int r, cookie_r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    SSL * ssl = nullptr;
    BIO * dgramBio = nullptr;
    socklen_t salen = sizeof(struct sockaddr);
    int assoc_id = 0;


    BIO_ADDR* client_addr_bio = BIO_ADDR_new();
    if (!client_addr_bio) {
        OSSLErrorHandler("ProcessSCTPTLSClientWithServerSocket(): BIO_ADDR_new(): cannot create BIO for client address");
        return;
    }

    dgramBio = BIO_new_dgram(server_sd, BIO_NOCLOSE);
    if (!dgramBio) {
        OSSLErrorHandler("ProcessSCTPTLSClientWithServerSocket(): BIO_new_dgram(): cannot create from fd");
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL){
        OSSLErrorHandler("ProcessSCTPTLSClientWithServerSocket(): SSL_new(): ");
        return;
    }

    // Now SSL will apply to all data coming from the file descriptor
    // From OpenSSL 1.1.1c docs:
    // The ssl parameter should be a newly allocated SSL
    // object with its read and write BIOs set, in the same way
    // as might be done for a call to SSL_accept(). Typically,
    // for DTLS, the read BIO will be in an "unconnected"
    // state and thus capable of receiving messages from any peer.
    SSL_set_bio(ssl, dgramBio, dgramBio);
    SSL_set_accept_state(ssl);

    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);


    #ifdef DEBUG
    printf("DTLS Listening ...\n");
    #endif

    do {
        cookie_r = DTLSv1_listen(ssl, client_addr_bio);
    }    while (!cookie_r);
    if (cookie_r < 0) {
        OSSLErrorHandler("ProcessSCTPTLSClientWithServerSocket(): DTLSv1_listen(): ");
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }
    assoc_id = GetSCTPAssociationID(server_sd, (sockaddr *)client_addr_bio, salen);
    if (assoc_id == -1) {
        OSSLErrorHandler("ProcessSCTPTLSClientWithServerSocket(): GetSCTPAssociationID(): ");
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }
    #ifdef DEBUG
    std::cout << "Cookie exchange OK, DTLSv1_listen() returned " << cookie_r << std::endl;
    std::cout << "SCTP association ID: " << assoc_id << std::endl;
    #endif

    // We don't need to do the following because SCTP is a connect-based protocol
    // set BIO to connected
    // if (!BIO_connect(server_sd, client_addr_bio, 0)) {
    //     OSSLErrorHandler("ProcessSCTPTLSClientWithServerSocket(): BIO_connect(): ");
    //     SSL_free(ssl);
    //     BIO_ADDR_free(client_addr_bio);
    //     return;
    // }

    // Attempt to complete the DTLS handshake
    // If successful, the DTLS link state is initialized internally
    #ifdef DEBUG
    std::cout << "waiting for SSL_accept() " << std::endl;
    #endif

    int acc_r = SSL_accept(ssl);
    if (acc_r <= 0)  {
        OSSLErrorHandler("ProcessDTLSClient(): SSL_accept(): ");
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }
    #ifdef DEBUG
    std::cout << "SSL_accept() ok, returned " << acc_r << std::endl;
    #endif

    r = ReceiveMessageTLS(ssl, buff);
    if (r == -1) {
        perror("ProcessTLSClient(): ReceiveMessageTLS()");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendStringSize(reversed string)");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendString(reversed string)");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    #ifdef DEBUG
        std::cout <<  "--> ProcessTLSClient(): OK, reversed string: "
        << buff << std::endl;
    #endif
    SSL_shutdown(ssl);
    SSL_free(ssl);
    BIO_ADDR_free(client_addr_bio);
    return;
}
