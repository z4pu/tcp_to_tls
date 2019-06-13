#ifndef CLIENT_SCTP_HELPER_ONE_TO_MANY_TLS_HPP
#define CLIENT_SCTP_HELPER_ONE_TO_MANY_TLS_HPP

extern "C" {
    #include <netinet/in.h>
}

extern "C" {
    #include <openssl/evp.h>
    #include <openssl/err.h>
    #include <openssl/ssl.h>
}

int SetPeerAsSCTPTLSEndpoint(const int &peer_fd, const sockaddr_in &peer_addr, SSL * const ssl);



#endif /* CLIENT_SCTP_HELPER_ONE_TO_MANY_TLS_HPP */
