#ifndef CLIENT_TLS_HELPER_HPP
#define CLIENT_TLS_HELPER_HPP

extern "C" {
    #include <openssl/ssl.h>
}

#define CLIENT_CERTIFICATE "../certs/client.crt"
#define CLIENT_PRIVATEKEY "../certs/client.key"

SSL_CTX*  TlsInitClientContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

int SendRequestTLS(SSL * const ssl, const char * string);

#endif /* CLIENT_TLS_HELPER_HPP */
