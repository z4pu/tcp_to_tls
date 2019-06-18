#include "server_udp_helper.hpp"
#include "common_udp.hpp"
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
#include <string>

/**
* @brief Listens on specified TCP port for specified number of connections
* @param [in] port TCP port to listen on
* @param [in] backlog maximum number of incoming connections to handle
* @return -1 if error, file descriptor of socket if successful
*/

int UDPBind(const int& port)
{
	int sd, reuseaddr, status;
	struct addrinfo hints, * ai, * aptr;
	char port_str[6] = {0};
    //struct timeval tv;
    //tv.tv_sec = TIMEOUT_IN_SECS;
    //tv.tv_usec = 0;


	if ((port > 65535) || (port < 1)) {
    std::cerr << "UDPBind(): Invalid port number\n";
    return -1;
  }

  if (!port) {
    std::cerr << "UDPBind(): Null params\n";
    return -1;
  }
	sprintf(port_str, "%d", port);

	/* Initialise Hints - Address struct*/
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE ; /* passive open */
	hints.ai_family = AF_UNSPEC ; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM ; /* TCP - Socket */
    hints.ai_protocol = IPPROTO_UDP;

	/* fill Address struct for passive socket */
	if ((status = getaddrinfo(nullptr, port_str, &hints, &ai)) == 0)
	{
			for (aptr = ai; aptr != NULL; aptr = aptr->ai_next ) {
				if (( sd = socket(aptr->ai_family,
					aptr->ai_socktype, aptr->ai_protocol)) < 0 )
					continue; /* If error, go to next Address struct */

				/* To avoid "address already in use" Error */
				reuseaddr = 1;
				setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));

                // Add timeout value
                //setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

				if (bind (sd, aptr->ai_addr, aptr->ai_addrlen ) == -1 ) {
                    close(sd);
                    perror("UDPBind(): bind");
                    continue;
                }

			    /* End loop if successful */
				break;
			}

			freeaddrinfo(ai);

			/*
			* If list is processed unsucessfully, aptr = NULL
			* and errno shows the error in the last call to von
			* socket () , bind ()
			*/
			if (aptr == NULL){
                std::cerr << "UDPBind(): ";
				fprintf(stderr, "Can’t bind to port %s :%s\n",
							port_str, strerror(errno));
				return(-1);
			}
		}
	else	{
      std::cerr << "UDPBind(): ";
			fprintf(stderr, "getaddrinfo () failed : %s \n", gai_strerror(status));
			return ( -1 );
	}
	return (sd);
}

int ProcessUDPClient (const int& server_sd)
{
    socklen_t peer_addr_len;
    struct sockaddr_storage peer_addr;
    int r, s, c = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    char host[NI_MAXHOST], service[NI_MAXSERV];

    peer_addr_len = sizeof(struct sockaddr_storage);

    r = recvfrom(server_sd, buff, MAX_STRING_LENGTH, 0,
                (struct sockaddr *) &peer_addr, &peer_addr_len);
    if (r == -1)   {
        perror("ProcessUDPClient(): recvfrom()");
        return -1;
    }
    std::cout << "--> ProcessUDPClient(): incoming string "
        << buff << std::endl;

    s = getnameinfo((struct sockaddr *) &peer_addr,
        peer_addr_len, host, NI_MAXHOST,
        service, NI_MAXSERV, NI_NUMERICSERV);
    if ( s == 0) {
        printf("ProcessUDPClient(): Received %ld bytes from %s:%s\n", (long)r, host, service);
    } else {
        fprintf(stderr, "ProcessUDPClient(): getnameinfo: %s\n", gai_strerror(s));
        return -1;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    c = sendto(server_sd, buff, r, 0,  (struct sockaddr *) &peer_addr,
            peer_addr_len);
    if (c != r) {
        perror("ProcessUDPClient(): sendto(): Error sending response");
        return -1;
    }

    std::cout << "--> ProcessUDPClient(): sent reversed string "
        << buff << std::endl;

    return 0;
}
