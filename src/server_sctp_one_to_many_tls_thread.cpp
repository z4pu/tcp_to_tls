#include "server_sctp_helper_one_to_many.hpp"
#include "server_sctp_helper_one_to_many_tls.hpp"
#include "common.hpp"
#include "common_tls.hpp"
#include "common_sctp.hpp"
#include "server_tls_helper.hpp"
#include "server_dtls_helper.hpp"
#include "thread_helper.hpp"
#include "thread_tls_helper.hpp"
#include "thread_sctp_one_to_many_tls_helper.hpp"
#include "ck_secrets_vault.h"
#include "thread_dtls_helper.hpp"



#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

extern "C" {
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netinet/sctp.h>
}

extern "C" {
    #include <unistd.h>
    #include <signal.h>
    #include <pthread.h>
}

extern "C" {
    #include "pthread_wrap.h"
}
pthread_mutex_t sd_mutex;
pthread_mutex_t ctx_lock;
pthread_mutex_t ssl_lock;
pthread_mutex_t *crypto_mutexes = NULL;
BIO *bio_err;

bool server_on;
int Usage(int err, char *argv[]);


int main(int argc, char *argv[])
{
    int err, assoc_id = 0;
    int sd, server_port, status, r = 0;
    sctp_one_to_many_client_thread_args args;
    SSL_CTX* ctx = nullptr;
    sigset_t sigset;
    pthread_t tid_sig_handler;
    void * tret;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    memset(&args, 0, sizeof(struct sctp_one_to_many_client_thread_args));
    pthread_t tid = {};
    SSL *ssl = nullptr;
    BIO * dgramBio;
    struct timeval timeout;
    server_on = true;
    socklen_t client_addr_size = sizeof(client_addr);

    // As of version 1.1.0 OpenSSL will automatically allocate all
    // resources that it needs so no explicit initialisation is required.
    // https://wiki.openssl.org/index.php/Library_Initialization
    setup_openssl_thread_support();
    bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

    if (argc==3)  {
        if (strcmp(argv[1],"-p")==0)        {
            printf("Command-line arguments ok.\n\n");
        }
        else {
            Usage(err, &argv[0]);
            return 0;
        }
    }
    else {
        Usage(err, &argv[0]);
        return 0;
    }

    server_port = atoi(argv[2]);

    std::cout << "Generated " << ck_secrets_generate(CK_SECRET_MAX) << " cookie-secrets for DTLS\n";

    sd = SCTPListenOneToMany(server_port, NUM_CLIENTS);
    std::cout << "Server sd: " << sd << std::endl;
    if (sd == -1) return -1;

    // Subscribe to SCTP notifications to track association ids

    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    BuildAddress(server_addr, server_port, "0.0.0.0");

    ctx = DTLSInitServerContextFromKeystore(ctx, SERVER_CERTIFICATE,
        SERVER_PRIVATEKEY, TRUSTED_CA_CERTS_FILE);
    if (!ctx) return -1;

    mutexInit(&sd_mutex, NULL);
    mutexInit(&ctx_lock, NULL);
    mutexInit(&ssl_lock, NULL);

    /* Signalmask initialise */
    /* Block all signals in this thread and child threads */
    sigfillset(&sigset);
    status = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if (status != 0)  {
        fprintf(stderr, "pthread_sigmask() failed : %s", strerror(status));
        goto end;
    }
    /* start the signal handler */
    tid_sig_handler = createThread(DTLSSignalHandler, NULL);
    printf("TID %lu\t: Created Signal Thread ID %lu\n",
    	(unsigned long)pthread_self(), (unsigned long)tid_sig_handler);

    while (server_on) { // Set up BIOs and SSL for cookie exchange
        memset(&client_addr, 0, sizeof(struct sockaddr_in));
        assoc_id = 0;

		/* Create BIO */
        mutexLock(&sd_mutex);
		dgramBio = BIO_new_dgram_sctp(sd, BIO_NOCLOSE);
        if (!dgramBio) {
            OSSLErrorHandler("main(): BIO_new_dgram_sctp(): cannot create from fd");
            mutexUnlock(&sd_mutex);
            goto end;
        }
        mutexUnlock(&sd_mutex);

		/* Set and activate timeouts */
		timeout.tv_sec = TIMEOUT_IN_SECS;
		timeout.tv_usec = 0;
		BIO_ctrl(dgramBio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        mutexLock(&ctx_lock);
		ssl = SSL_new(ctx);
        if (ssl == NULL){
            OSSLErrorHandler("main(): SSL_new(): ");
            mutexUnlock(&ctx_lock);
            goto end;
        }
        mutexUnlock(&ctx_lock);

		SSL_set_bio(ssl, dgramBio, dgramBio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
        do {
            r = DTLSv1_listen(ssl, (BIO_ADDR *) &client_addr);
        }    while (!r && server_on);
        if (r < 0 || !server_on) {
            OSSLErrorHandler("main(): DTLSv1_listen(): ");
            goto end;
        }

        #ifdef DEBUG
        std::cout<< std::endl <<"Cookie exchange with " << inet_ntoa(client_addr.sin_addr) << ":" << ntohs(client_addr.sin_port) << " OK!"<<  std::endl;
        #endif

        assoc_id = get_associd(sd, (sockaddr*)&client_addr, client_addr_size);
    	if (r < 0) {
    		perror("SCTPTLSOneToManyClientThread(): getsockopt(SCTP_STATUS)");
    		goto end;
    	}

        #ifdef DEBUG
        std::cout<< std::endl <<"Association ID " << assoc_id << " established" <<  std::endl;
        #endif

        memcpy(&args.client_addr, &client_addr, sizeof(struct sockaddr_in));
        args.ssl = ssl;
        args.ctx = ctx;
        args.server_sd = sd;
        args.peer_assoc_id = assoc_id;

        status = pthread_create(&tid, NULL, SCTPTLSOneToManyClientThread, (void *)&args);
        if (status != 0)    {
            printf("pthread_create() failed : %s\n", strerror(status));
            goto end;
        }

    }


    end:
    // JOIN SIGNAL THREAD
    joinThread(tid_sig_handler, &tret);
    printf("Main TID %lu\t: joined signal thread\n", (unsigned long)pthread_self());

    if (ctx) SSL_CTX_free(ctx);
    if (sd) close(sd);
    return 0;
}

/**
* @brief Command-line usage instructions
* @param [in] err Error message
* @param [in] argv[] Arguments to command-line when starting program
* @return err
*/
int Usage(int err, char *argv[])
{
    printf("\n[main] : syntax error !\n");
    printf("\nSYNTAX: %s -p <port to listen>\n\n",argv[0]);
    return err;
}
