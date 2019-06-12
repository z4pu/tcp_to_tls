#include "client_sctp_helper.hpp"
#include "common_sctp.hpp"
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
* @brief Connects to a SCTP server listening at the specified address and port using a one-to-one socket
* @param [in] port Port where server is listening
* @param [in] addr String containing IP address
* @return -1 if error, 0 if successful
*/
int SCTPConnectOneToOne(const int& port, const char * addr){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_SCTP;
    char port_str[6] = {0};
    sprintf(port_str, "%d", port);


    if ((rv = getaddrinfo(addr, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "SCTPConnectOneToOne(): getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("SCTPConnectOneToOne(): socket()");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("SCTPConnectOneToOne(): connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "SCTPConnectOneToOne(): failed to connect\n");
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("SCTPConnectOneToOne(): client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

	#ifdef DEBUG
		std::cout << "--> Connected blocking SCTP socket fd: " << sockfd << std::endl;
	#endif

    return sockfd;
}

/**
* @brief Connects to a SCTP server listening at the specified address and port using a many-to-one socket
* @param [in] port Port where server is listening
* @param [in] addr String containing IP address
* @return -1 if error, 0 if successful
*/
int SCTPConnectManyToOne(const int& port, const char * addr){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_SEQPACKET;
    hints.ai_protocol = IPPROTO_SCTP;
    char port_str[6] = {0};
    sprintf(port_str, "%d", port);


    if ((rv = getaddrinfo(addr, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "SCTPConnectManyToOne(): getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("SCTPConnectManyToOne(): socket()");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "SCTPConnectManyToOne(): failed to connect\n");
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("SCTPConnectManyToOne(): client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

	#ifdef DEBUG
		std::cout << "--> Connected blocking SCTP socket fd: " << sockfd << std::endl;
	#endif

    return sockfd;
}
