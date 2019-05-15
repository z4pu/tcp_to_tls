#ifndef SERVER_TLS_HELPER_HPP
#define SERVER_TLS_HELPER_HPP

extern "C" {
    #include <openssl/ssl.h>
}

#define SERVER_CERTIFICATE "../certs/server.crt"
#define SERVER_PRIVATEKEY "../certs/server.key"

SSL_CTX* TlsInitServerContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

void ProcessTLSClient (SSL * const ssl);

#endif /* SERVER_TLS_HELPER_HPP */
