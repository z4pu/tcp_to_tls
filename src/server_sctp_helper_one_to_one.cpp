#include "server_sctp_helper_one_to_one.hpp"
#include "common.hpp"
#include "common_sctp.hpp"

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
* @brief Listens on specified TCP port for specified number of connections. Creates an SCTP one-to-one socket
* @param [in] port TCP port to listen on
* @param [in] backlog maximum number of incoming connections to handle
* @return -1 if error, file descriptor of socket if successful
*/

int SCTPListenOneToOne(const int& port, const int& backlog)
{
	int sd, reuseaddr, status;
	struct addrinfo hints, * ai, * aptr;
	char port_str[6] = {0};
    //struct timeval tv;
    //tv.tv_sec = TIMEOUT_IN_SECS;
    //tv.tv_usec = 0;


	if ((port > 65535) || (port < 1)) {
    std::cerr << "SCTPListenOneToOne(): Invalid port number\n";
    return -1;
  }

  if (!port || !backlog) {
    std::cerr << "SCTPListenOneToOne(): Null params\n";
    return -1;
  }
	sprintf(port_str, "%d", port);

	/* Initialise Hints - Address struct*/
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_PASSIVE ; /* passive open */
	hints.ai_family = AF_UNSPEC ; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM ; /* TCP - Socket */
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
				setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int));

                // Add timeout value
                //setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

                if (bind (sd, aptr->ai_addr, aptr->ai_addrlen ) == -1 ) {
                    close(sd);
                    perror("SCTPListenOneToOne(): bind");
                    continue;
                }

				/* Change passive socket to active socket */
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
        std::cerr << "SCTPListenOneToOne(): ";
				fprintf(stderr, "Can’t listen on port %s :%s\n",
							port_str, strerror(errno));
				return(-1);
			}
		}
	else	{
      std::cerr << "SCTPListenOneToOne(): ";
			fprintf(stderr, "getaddrinfo () failed : %s \n", gai_strerror(status));
			return ( -1 );
	}
	return (sd);
}


void ProcessSCTPClientWithClientSocket (const int& client_socket) {
    int r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    //std::string instring, outstring;

    r = RecvSCTP(client_socket, buff);
    if (r == -1) {
        perror("ProcessSCTPClientWithClientSocket(): recv()");
        return;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendSCTP(client_socket, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessSCTPClientWithClientSocket(): send(reversed string)");
        return;
    }

    return;
}
