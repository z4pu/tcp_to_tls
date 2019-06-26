#include "server_sctp_helper_one_to_one.hpp"
#include "server_tls_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"
#include "common_sctp.hpp"

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
    int sd, client_sd, server_port, r, assoc_id = 0;
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

    sd = SCTPListenOneToOne(server_port, NUM_CLIENTS);
    if (sd == -1) return -1;

    ctx = TLSInitServerContextFromKeystore(ctx, SERVER_CERTIFICATE,
        SERVER_PRIVATEKEY, TRUSTED_CA_CERTS_FILE);
    if (!ctx) return -1;

    for (;;) {
        slen = sizeof(sockaddr_in);
        client_sd = accept(sd, (struct sockaddr *)&sa,	&slen);
        if (client_sd < 0){
            perror("accept() failed");
            return -1;
        }
        std::cout << "--> accept(): New FD " << client_sd <<  " created from "
        << inet_ntoa(sa.sin_addr) << " at port " << ntohs(sa.sin_port) << std::endl;

        assoc_id = GetSCTPAssociationID(client_sd, (sockaddr *)&sa, sizeof(sockaddr_in));
        if (assoc_id == -1) {
            perror("GetSCTPAssociationID(): ");
            close(sd);
            return 0;
        }
        std::cout << "SCTP association ID: " << assoc_id << std::endl;

        ssl = SSL_new(ctx);
    	if (ssl == NULL){
    		OSSLErrorHandler("SSL_new(): Error creating new SSL from ctx");
    		close(client_sd);
            continue;
    	}

        // sets client_sd as the input/output facility for the TLS/SSL
        // (encrypted) side of ssl
        // Creates a socket BIO to interface between the ssl and file
        // descriptor
        if (!SSL_set_fd(ssl, client_sd)) {
            OSSLErrorHandler("SSL_set_fd(client_sd)");
            SSL_shutdown(ssl);
   		    SSL_free(ssl);
    		close(client_sd);
            continue;
        }
        std::cout << "--> SSL_set_fd: OK" << std::endl;

        // waits for a TLS/SSL client to initiate the TLS/SSL handshake
        if (SSL_accept(ssl) <= 0) {
      	     OSSLErrorHandler("SSL_accept()");
             SSL_shutdown(ssl);
    		 SSL_free(ssl);
             close(client_sd);
             continue;
  	     }
         std::cout << "TLS client accepted" << std::endl;
         ProcessTLSClient(ssl);
         SSL_shutdown(ssl);
		 SSL_free(ssl);
        close(client_sd);
    }

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
