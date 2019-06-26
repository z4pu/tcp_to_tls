#include "server_sctp_helper_one_to_one.hpp"
#include "common.hpp"
#include "common_sctp.hpp"


#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <iostream>

extern "C" {
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
}

extern "C" {
    #include <unistd.h>
}

int Usage(int err, char *argv[]);


int main(int argc, char *argv[])
{
    int err = 0;
    int sd, client_sd, server_port, assoc_id = 0;
    socklen_t slen ;
	sockaddr_in	sa;

    if (argc==3)  {
        if (strcmp(argv[1],"-p")==0)        {
            printf("Command-line arguments ok.\n\n");
        }
        else {
            Usage(err, &argv[0]);
            return 0;
        }
    }
    else {
        Usage(err, &argv[0]);
        return 0;
    }

    server_port = atoi(argv[2]);

    sd = SCTPListenOneToOne(server_port, NUM_CLIENTS);
    if (sd == -1) return -1;


    for (;;) {
        slen = sizeof(sockaddr_in);
        client_sd = accept(sd, (struct sockaddr *)&sa,	&slen);
        if (client_sd < 0){
            perror("accept() failed");
            return -1;
        }
        std::cout << "--> accept(): New FD " << client_sd <<  " created from "
        << inet_ntoa(sa.sin_addr) << " at port " << ntohs(sa.sin_port) << std::endl;

        assoc_id = GetSCTPAssociationID(client_sd, (sockaddr *)&sa, sizeof(sockaddr_in));
        if (assoc_id == -1) {
            perror("GetSCTPAssociationID(): ");
            return -1;
        }
        std::cout << "SCTP association ID: " << assoc_id << std::endl;

        ProcessSCTPClientWithClientSocket (client_sd);
        close(client_sd);
    }

    close(sd);
    return 0;
}

/**
* @brief Command-line usage instructions
* @param [in] err Error message
* @param [in] argv[] Arguments to command-line when starting program
* @return err
*/
int Usage(int err, char *argv[])
{
    printf("\n[main] : syntax error !\n");
    printf("\nSYNTAX: %s -p <port to listen>\n\n",argv[0]);
    return err;
}
