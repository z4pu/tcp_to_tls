#ifndef SERVER_SCTP_HELPER_ONE_TO_MANY_TLS_HPP
#define SERVER_SCTP_HELPER_ONE_TO_MANY_TLS_HPP

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

void ProcessSCTPTLSClientWithServerSocket (const int& server_sd, SSL_CTX* const ctx);


#endif /* SERVER_SCTP_HELPER_ONE_TO_MANY_TLS_HPP */
