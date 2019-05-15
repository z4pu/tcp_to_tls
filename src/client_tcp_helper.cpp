#include "client_tcp_helper.hpp"
#include "common.hpp"

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
}

extern "C" {
    #include <unistd.h>
}

#include <iostream>

/**
* @brief Connects to a server listening at the specified address and port.
* @param [in] port Port where server is listening
* @param [in] addr String containing IP address
* @return -1 if error, 0 if successful
*/
int TCPConnect(const int& port, const char * addr){
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[6] = {0};
    sprintf(port_str, "%d", port);


    if ((rv = getaddrinfo(addr, port_str, &hints, &servinfo)) != 0) {
        fprintf(stderr, "TCPConnect(): getaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("TCPConnect(): socket()");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            perror("TCPConnect(): connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "TCPConnect(): failed to connect\n");
        return -1;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    printf("client: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure

	#ifdef DEBUG
		std::cout << "--> Connected blocking socket fd: " << sockfd << std::endl;
	#endif

    return sockfd;
}

int SendRequest(const int& socket, const char * string)
{
    int r, string_length = 0;
    string_length = SendStringSize(socket, string);
    if (string_length == -1) {
        perror("SendRequest(): SendStringSize()");
        return -1;
    }
    r = SendString(socket, string);
    if (r == -1){
        perror("SendRequest(): SendString()");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "--> SendRequest(): " << string << std::endl;
    #endif
    return 0;
}
