#include "server_sctp_helper_one_to_many.hpp"
#include "server_sctp_helper_one_to_many_tls.hpp"
#include "common.hpp"
#include "common_tls.hpp"
#include "server_tls_helper.hpp"
#include "server_dtls_helper.hpp"

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
}

extern "C" {
    #include <unistd.h>
    #include <signal.h>
}

BIO *bio_err;


int Usage(int err, char *argv[]);


int main(int argc, char *argv[])
{
    int err = 0;
    int sd, server_port, r = 0;
    SSL_CTX* ctx = nullptr;
    sigset_t sigset;

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

    sd = SCTPListenOneToMany(server_port, NUM_CLIENTS);
    if (sd == -1) return -1;

    ctx = DTLSInitServerContextFromKeystore(ctx, SERVER_CERTIFICATE,
        SERVER_PRIVATEKEY, TRUSTED_CA_CERTS_FILE);
    if (!ctx) return -1;



    for (;;) {
        ProcessSCTPTLSClientWithServerSocket(sd, ctx);
    }

    SSL_CTX_free(ctx);
    close(sd);
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
