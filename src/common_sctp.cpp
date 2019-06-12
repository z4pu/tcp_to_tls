#include "common_sctp.hpp"
#include "common.hpp"

#include <cerrno>
#include <cstdio>
#include <iostream>

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
    #include <netinet/sctp.h>
}

/**
* @brief Receives an SCTP message
* @param [in] socket SCTP socket file descriptor
* @param [in] inbuff pointer to the start of a buffer that will contain the message
* @return -1 if error, the length of the message if successful
*/
int RecvSCTP(const int& socket, unsigned char * const inbuff) {
    int r  = 0;

    r = recv(socket, inbuff, MAX_STRING_LENGTH, 0);
    if (r == -1){
        perror("RecvSCTP(): recv()");
        return -1;
    }
    #ifdef DEBUG
        std::cout << "--> RecvSCTP(): " << inbuff << std::endl;
    #endif
    return r;
}

int SendSCTP(const int& socket, const char * string)
{
    int r = 0;

    r = send(socket, string, strlen(string), 0);
    if (r == -1){
        perror("SendSCTP(): send()");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "--> SendSCTP(): " << string << std::endl;
    #endif
    return 0;
}
