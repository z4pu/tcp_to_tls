#include "server_udp_helper.hpp"
#include "server_tls_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
}

extern "C" {
    #include <unistd.h>
    #include <signal.h>
}

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

BIO *bio_err;

int Usage(int err, char *argv[]);


int main(int argc, char *argv[])
{
    int err, r = 0;
    int sd, server_port = 0;
    socklen_t slen ;
	sockaddr_in	sa;
    SSL *ssl;
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

    // As of version 1.1.0 OpenSSL will automatically allocate all
    // resources that it needs so no explicit initialisation is required.
    // https://wiki.openssl.org/index.php/Library_Initialization
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

    sd = UDPBind(server_port);
    if (sd == -1) return -1;

    ctx = DTLSInitServerContextFromKeystore(ctx, SERVER_CERTIFICATE,
        SERVER_PRIVATEKEY, TRUSTED_CA_CERTS_FILE);
    if (!ctx) return -1;

    for (;;) {
        ProcessDTLSClient(sd, ctx);
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
