#include "common.hpp"
#include "common_tls.hpp"
#include "client_udp_helper.hpp"
#include "client_dtls_helper.hpp"
#include "client_tls_helper.hpp"


#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <iostream>

extern "C" {
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netinet/sctp.h>
}

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

BIO *bio_err;

int Usage(char *argv[]);


int main(int argc, char *argv[]){
    int srv_port, sd, r, err = 0;
    unsigned char received_string[MAX_STRING_LENGTH+1] = {};
    sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(sockaddr_in));
    SSL *ssl;
    SSL_CTX* ctx = nullptr;

    bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

    if (argc!=7)  {
        Usage(&argv[0]);
        return 0;
    }
    else {
        if (strcmp(argv[1],"-h") != 0
            || strcmp(argv[3],"-p") != 0
            || strcmp(argv[5],"-s") != 0
        )  {
                Usage(&argv[0]);
                return 0;
        }
        else {
            ctx = DTLSInitClientContextFromKeystore(ctx,
                CLIENT_CERTIFICATE, CLIENT_PRIVATEKEY, TRUSTED_CA_CERTS_FILE);
            if (!ctx) return -1;

            srv_port = atoi(argv[4]);

            BuildAddress(peer_addr, srv_port, argv[2]);

            if ((sd = UDPClientSocket(srv_port, argv[2])) < 0){
                perror("main(): UDPClientSocket()");
                return 0;
            }

            ssl = SSL_new(ctx);
            if (ssl == NULL){
                OSSLErrorHandler("SSL_new(): Error creating new SSL from ctx");
                close(sd);
                return 0;
            }

            r = SetPeerasTLSEndpoint(sd, peer_addr, ssl);
            if (r == -1) {
                OSSLErrorHandler("SetPeerasTLSEndpoint()");
                SSL_free(ssl);
                close(sd);
                SSL_CTX_free(ctx);
                return 0;
            }

            SSL_set_connect_state(ssl);

            r = SSL_do_handshake(ssl);
            if (r != 1) {
                err = SSL_get_error(ssl, r);
                OSSLErrorHandler("SSL_do_handshake");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sd);
                SSL_CTX_free(ctx);
                return 0;
            }
            std::cout << "Handshake ok" << std::endl;

            r = SendRequestTLS(ssl, argv[6]);
            if (r == -1) {
              perror("main(): SendRequestTLS()");
              SSL_shutdown(ssl);
              SSL_free(ssl);
              close(sd);
              SSL_CTX_free(ctx);
              return 0;
            }

            r = ReceiveMessageTLS(ssl, received_string);
            if (r == -1) {
              perror("main(): ReceiveMessageTLS()");
              SSL_shutdown(ssl);
              SSL_free(ssl);
              close(sd);
              SSL_CTX_free(ctx);
              return 0;
            }

            std::cout << "Reversed string: " << received_string << std::endl;
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sd);
        }
    }
    SSL_CTX_free(ctx);
    return 0;
}

int Usage(char *argv[]){
  printf("\n[main] : syntax error !\n");
    printf("\nSYNTAX: %s \n"
    "-h <server IPv4 address>\n"
    "-p <listening port of server>\n"
    "-s <string to send>\n"
    "\n", argv[0]);
    return 0;
}
