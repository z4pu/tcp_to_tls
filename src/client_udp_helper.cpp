#include "client_udp_helper.hpp"
#include "common.hpp"

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
/**
* @brief Gets a socket for a UDP server bound to the specified address and port
* @param [in] port Port where server is listening
* @param [in] addr String containing IP address
* @return -1 if error, 0 if successful
*/
int UDPClientSocket(const int& port, const char * addr){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    char port_str[6] = {0};
    sprintf(port_str, "%d", port);


    if ((rv = getaddrinfo(addr, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "UDPClientSocket(): getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("UDPClientSocket(): socket()");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "UDPClientSocket(): failed to connect\n");
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("UDPClientSocket(): client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

	#ifdef DEBUG
		std::cout << "--> Created UDP socket fd: " << sockfd << std::endl;
	#endif

    return sockfd;
}
