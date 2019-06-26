#include "server_sctp_helper_one_to_one.hpp"
#include "server_tls_helper.hpp"
#include "thread_sctp_one_to_one_tls_helper.hpp"
#include "thread_helper.hpp"
#include "thread_tls_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include "pthread_wrap.h"
}

extern "C" {
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
}

extern "C" {
    #include <unistd.h>
    #include <signal.h>
    #include <pthread.h>
}



pthread_mutex_t sd_mutex;
pthread_mutex_t ctx_lock;
pthread_mutex_t *crypto_mutexes = NULL;
BIO *bio_err;

int Usage(int err, char *argv[]);


int main(int argc, char *argv[])
{
    int err = 0;
    int sd, server_port, r, status = 0;
    tls_client_thread_args args;
    SSL_CTX* ctx = nullptr;
    sigset_t sigset;
    pthread_t tid[MAX_CLIENTS] = {};

    /* Signalmask initialise */
    /* Block SIGPIPE if client breaks connection; other threads created by main()
    will inherit a copy of the signal mask. */
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);

    r = sigprocmask(SIG_SETMASK, &sigset, nullptr);
    if (r == -1) {
        perror("Could not block SIGPIPE");
        return 0;
    }

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

    sd = SCTPListenOneToOne(server_port, NUM_CLIENTS);
    if (sd == -1) return -1;

    ctx = TLSInitServerContextFromKeystore(ctx, SERVER_CERTIFICATE,
        SERVER_PRIVATEKEY, TRUSTED_CA_CERTS_FILE);
    if (!ctx) return -1;

    mutexInit(&sd_mutex, NULL);
    mutexInit(&ctx_lock, NULL);

    /* Signalmask initialise */
    /* Block SIGPIPE; other threads created by main()
    will inherit a copy of the signal mask. */
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);

    /* Set Signalmask for main () - Thread*/
    status = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if (status != 0)  {
        fprintf(stderr, "pthread_sigmask() failed : %s", strerror(status));
        goto end;
    }

    // Generate Pool of worker threads to accept and handle client connections
    for (int i = 0; i < MAX_CLIENTS; i++ )  {
        /* Start accept_handler (SIGTERM blocked) */
        args.server_sd = sd;
        args.ctx = ctx;

        status = pthread_create(&tid[i], NULL, SCTPTLSOneToOneClientThread, (void *)&args);
        if (status != 0)    {
            printf("pthread_create() failed : %s\n", strerror(status));
            close(sd); /* passive Socket closed */
            goto end;
        }
    }
    SignalCatcher(nullptr); /* Main thread handles signal */

    end:
    std::cout << "Shutting down server" << std::endl;

    for (int i = 0; i < MAX_CLIENTS; i++ ){
        status = pthread_cancel(tid[i]);
        std::cout << "Tried to cancel "<< tid[i] << std::endl;
        if (status != 0)  {
            fprintf(stderr, "pthread_cancel() failed : %s\n", strerror(status));
        }
        status = pthread_join(tid[i], nullptr);
        std::cout << "Tried to join "<< tid[i] << std::endl;
        if (status != 0)  {
            fprintf(stderr, "pthread_join() failed : %s\n", strerror(status));
        }
    }

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
