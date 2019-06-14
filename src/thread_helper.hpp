#ifndef THREAD_HELPER_HPP
#define THREAD_HELPER_HPP

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

extern "C" {
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
}

struct tcp_client_thread_args{
  int server_sd;
  int connection_number;
};

struct tls_client_thread_args{
  int server_sd;
  SSL_CTX * ctx;
};

struct dtls_client_thread_args{
  int sd;
  SSL_CTX * ctx;
  SSL * ssl;
  BIO * readBio;
  BIO * writeBio;
  struct sockaddr_storage peer_addr;
  int connection_number;
};

extern pthread_mutex_t sd_mutex;
extern pthread_mutex_t *crypto_mutexes;
extern pthread_mutex_t ctx_lock;

void * SignalCatcher(void * arg);

#endif /* THREAD_HELPER_HPP */
