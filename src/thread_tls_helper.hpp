#ifndef THREAD_TLS_HELPER_HPP
#define THREAD_TLS_HELPER_HPP

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

void * TLSClientThread(void* args);

void setup_openssl_thread_support(void);
void HandleTLSClientInThread(const int& client_sd, SSL_CTX * ctx);

#endif /* THREAD_TLS_HELPER_HPP */
