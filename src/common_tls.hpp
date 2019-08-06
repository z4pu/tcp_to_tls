#ifndef COMMON_TLS_HPP
#define COMMON_TLS_HPP

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

#define FULLCIPHERLIST "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384"

// At compile time, the -Dname=value option is used to select the appropriate code blocks and generate the executable.
#ifdef DEBIAN
  #define TRUSTED_CA_CERTS_FILE "/etc/ssl/certs/ca-certificates.crt"
#endif
#ifdef CENTOS
  #define TRUSTED_CA_CERTS_FILE "/etc/pki/tls/certs/ca-bundle.crt"
#endif

extern BIO *bio_err;



int OSSLErrorHandler(const char * string);

int SSLReadWriteErrorHandler(SSL* const ssl, int readwritten);

SSL_CTX * LoadECParamsInContext(SSL_CTX *c);


int ReceiveSizeOfIncomingMessageTLS(SSL* const ssl);

int SendStringSizeTLS(SSL* const ssl, const char * string_to_send);

int SendStringTLS(SSL* const ssl, const char * string);

int ReceiveMessageTLS(SSL* const ssl, unsigned char * const inbuff);


#endif /* COMMON_TLS_HPP */
