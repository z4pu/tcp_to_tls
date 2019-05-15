#ifndef COMMON_TLS_HPP
#define COMMON_TLS_HPP

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

#define FULLCIPHERLIST "ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384"

#define TRUSTED_CA_CERTS_FILE "/etc/ssl/certs/ca-certificates.crt"

extern BIO *bio_err;



int OSSLErrorHandler(const char * string);

int SSLReadWriteErrorHandler(SSL* const ssl, int readwritten);

SSL_CTX * LoadECParamsInContext(SSL_CTX *c);


int ReceiveSizeOfIncomingMessageTLS(SSL* const ssl);

int SendStringSizeTLS(SSL* const ssl, const char * string_to_send);

int SendStringTLS(SSL* const ssl, const char * string);

int ReceiveMessageTLS(SSL* const ssl, unsigned char * const inbuff);


#endif /* COMMON_TLS_HPP */
