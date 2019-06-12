#ifndef SERVER_TLS_HELPER_HPP
#define SERVER_TLS_HELPER_HPP

extern "C" {
    #include <openssl/ssl.h>
}

#define SERVER_CERTIFICATE "../certs/server.crt"
#define SERVER_PRIVATEKEY "../certs/server.key"

SSL_CTX* TLSInitServerContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

SSL_CTX* DTLSInitServerContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

void ProcessTLSClient (SSL * const ssl);

void ProcessDTLSClient (const int &server_fd, SSL_CTX * const ctx);

int GenerateCookie( SSL *ssl, unsigned char *cookie,
  unsigned int *cookie_len );

int VerifyCookie( SSL *ssl, const unsigned char *cookie,
    unsigned int cookie_len );

#endif /* SERVER_TLS_HELPER_HPP */
