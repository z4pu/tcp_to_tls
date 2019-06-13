#ifndef CLIENT_DTLS_HELPER_HPP
#define CLIENT_DTLS_HELPER_HPP

extern "C" {
    #include <openssl/ssl.h>
    #include <netinet/in.h>
}



SSL_CTX*  DTLSInitClientContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* ca_cert_file);

int SetPeerAsDTLSEndpoint(const int &peer_fd, const sockaddr_in &ser_addr, SSL * const ssl);


#endif /* CLIENT_TLS_HELPER_HPP */
