#include "client_sctp_helper_one_to_many_tls.hpp"
#include "common_tls.hpp"

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
    #include <netinet/sctp.h>
}

extern "C" {
    #include <unistd.h>
}

#include <iostream>

int SetPeerAsSCTPTLSEndpoint(const int &peer_fd, const sockaddr_in &peer_addr, SSL * const ssl)
{
    BIO * dgramBio = nullptr;

    dgramBio = BIO_new_dgram(peer_fd, BIO_NOCLOSE);
    if (!dgramBio) {
        OSSLErrorHandler("SetPeerAsSCTPDTLSEndpoint(): BIO_new_dgram(): cannot set peer fd");
        return -1;
    }

    if (BIO_ctrl_dgram_connect(dgramBio, &peer_addr) == 0) {
        BIO_free(dgramBio);
        return -1;
    }

    SSL_set_bio(ssl, dgramBio, dgramBio);

    return 0;
}
