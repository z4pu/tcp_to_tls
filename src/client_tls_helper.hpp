#ifndef CLIENT_TLS_HELPER_HPP
#define CLIENT_TLS_HELPER_HPP

extern "C" {
    #include <openssl/ssl.h>
    #include <netinet/in.h>
}

#define CLIENT_CERTIFICATE "../certs/client.crt"
#define CLIENT_PRIVATEKEY "../certs/client.key"

SSL_CTX*  TLSInitClientContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

SSL_CTX*  DTLSInitClientContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

int SetPeerasTLSEndpoint(const int &peer_fd, const sockaddr_in &ser_addr, SSL * const ssl);

int SendRequestTLS(SSL * const ssl, const char * string);

#endif /* CLIENT_TLS_HELPER_HPP */
