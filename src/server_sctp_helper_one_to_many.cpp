#include "server_sctp_helper_one_to_many.hpp"
#include "common.hpp"
#include "common_sctp.hpp"

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <netinet/sctp.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
}

extern "C" {
    #include <unistd.h>
}

#include <iostream>
#include <string>


/**
* @brief Creates an SCTP one-to-many socket and listens on specified port to wait for clients
* @param [in] port port to listen on
* @param [in] backlog maximum number of incoming connections to handle
* @return -1 if error, file descriptor of socket if successful
*/

int SCTPListenOneToMany(const int& port, const int& backlog)
{
	int sd, reuseaddr, status, r;
	struct addrinfo hints, * ai, * aptr;

	char port_str[6] = {0};
    //struct timeval tv;
    //tv.tv_sec = TIMEOUT_IN_SECS;
    //tv.tv_usec = 0;


	if ((port > 65535) || (port < 1)) {
    std::cerr << "SCTPListenOneToMany(): Invalid port number\n";
    return -1;
  }

  if (!port || !backlog) {
    std::cerr << "SCTPListenOneToMany(): Null params\n";
    return -1;
  }
	sprintf(port_str, "%d", port);

	/* Initialise Hints - Address struct*/
	memset(&hints, 0, sizeof(hints));


	hints.ai_flags = AI_PASSIVE ; /* passive open */
	hints.ai_family = AF_UNSPEC ; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_SEQPACKET ; /* TCP - Socket */
    hints.ai_protocol = IPPROTO_SCTP;

	/* fill Address struct for passive socket */
	if ((status = getaddrinfo(nullptr, port_str, &hints, &ai)) == 0)
	{
			for (aptr = ai; aptr != NULL; aptr = aptr->ai_next )
			{
				if (( sd = socket(aptr->ai_family,
					aptr->ai_socktype, aptr->ai_protocol)) < 0 )
					continue; /* If error, go to next Address struct */

				/* To avoid "address already in use" Error */
				reuseaddr = 1;
				r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));
                if (r == -1) {
                    close(sd);
                    perror("SCTPListenOneToMany(): setsockopt(SO_REUSEADDR)");
                    continue;
                }
                r = enable_notifications(sd);
                if (r != 0) {
                    close(sd);
                    perror("SCTPListenOneToMany(): enable_notifications()");
                    continue;
                }
                // Add timeout value
                //setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

                if (bind (sd, aptr->ai_addr, aptr->ai_addrlen ) == -1 ) {
                    close(sd);
                    perror("SCTPListenOneToMany(): bind");
                    continue;
                }

				// /* Change passive socket to active socket */
				if (listen(sd, backlog) >= 0 )
					/* End loop if successful */
					break;
				/* If error, close socket ... */
				close(sd);
			}

			freeaddrinfo(ai);

			/*
			* If list is processed unsucessfull, aptr = NULL
			* and errno shows the error in the last call to von
			* socket () , bind () or listen ()
			*/
			if (aptr == NULL){
        std::cerr << "SCTPListenOneToMany(): ";
				fprintf(stderr, "Can’t listen on port %s :%s\n",
							port_str, strerror(errno));
				return(-1);
			}
		}
	else	{
      std::cerr << "SCTPListenOneToMany(): ";
			fprintf(stderr, "getaddrinfo () failed : %s \n", gai_strerror(status));
			return ( -1 );
	}
	return (sd);
}


void ProcessSCTPClientWithServerSocket (const int& server_sd)
{
    socklen_t peer_addr_len;
    struct sockaddr_storage peer_addr;
    int r, s, c = 0;
    char buff[MAX_STRING_LENGTH+1] = {};
    char host[NI_MAXHOST], service[NI_MAXSERV];

    peer_addr_len = sizeof(struct sockaddr_storage);


    r = RecvSCTPOneToManyMessage(
        server_sd, (struct sockaddr_in *) &peer_addr, buff);
    if (r == -1)   {
        perror("ProcessSCTPClientWithServerSocket(): recvfrom()");
        return;
    }
    std::cout << "--> ProcessSCTPClientWithServerSocket(): incoming string "
        << buff << std::endl;

    s = getnameinfo((struct sockaddr *) &peer_addr,
        peer_addr_len, host, NI_MAXHOST,
        service, NI_MAXSERV, NI_NUMERICSERV);
    if ( s == 0) {
        printf("ProcessSCTPClientWithServerSocket(): Received %ld bytes from %s:%s\n", (long)r, host, service);
    } else {
        fprintf(stderr, "ProcessSCTPClientWithServerSocket(): getnameinfo: %s\n", gai_strerror(s));
        return;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    c = SendSCTPOneToManyMessage(server_sd, (struct sockaddr_in *) &peer_addr,
            buff);
    if (c != r) {
        perror("ProcessSCTPClientWithServerSocket(): sendto(): Error sending response");
    }

    std::cout << "--> ProcessSCTPClientWithServerSocket(): sent reversed string "
        << buff << std::endl;

    return;
}
