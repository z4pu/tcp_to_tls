#ifndef THREAD_DTLS_HELPER_HPP
#define THREAD_DTLS_HELPER_HPP

#include "thread_helper.hpp"

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

#include <vector>

#define DTLS_BUFFSIZE 65536
#define PACK_SIZE 4096


#define PEER_RECV_TIMEMOUT_USEC 250000
#define PEER_RECV_TIMEOUT_SEC 0

extern pthread_mutex_t ssl_lock;
extern bool server_on;


void * DTLSSignalHandler(void * arg);

void * DTLSClientThread(void * arg);



#endif /* THREAD_DTLS_HELPER_HPP */
