
#include "common.hpp"
#include "common_sctp.hpp"
#include "client_sctp_helper_one_to_many.hpp"


#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <iostream>

extern "C" {
    #include <unistd.h>
    #include <netinet/in.h>
    #include <netinet/sctp.h>
}


int Usage(char *argv[]);


int main(int argc, char *argv[]){
    int srv_port, sd, r, assoc_id = 0;
    char received_string[MAX_STRING_LENGTH+1] = {};
    sockaddr_in peer_addr;
    memset(&peer_addr, 0, sizeof(sockaddr_in));

    if (argc!=7)  {
        Usage(&argv[0]);
        return 0;
    }
    else {
        if (strcmp(argv[1],"-h") != 0
            || strcmp(argv[3],"-p") != 0
            || strcmp(argv[5],"-s") != 0
        )  {
                Usage(&argv[0]);
                return 0;
        }
        else {
            srv_port = atoi(argv[4]);

            BuildAddress(peer_addr, srv_port, argv[2]);

            if ((sd = SCTPConnectManyToOne(srv_port, argv[2])) < 0){
                perror("main(): SCTPConnectManyToOne()");
                return 0;
            }

            // Send data
            r = SendSCTPOneToManyMessage(sd, &peer_addr, argv[6]);
            if (r == -1) {
              perror("main(): sendto()");
              close(sd);
              return 0;
            }
            std::cout << "Sent string: " << argv[6] << std::endl;

            assoc_id = GetSCTPAssociationID(sd, (sockaddr *)&peer_addr, sizeof(sockaddr_in));
            if (assoc_id == -1) {
                perror("GetSCTPAssociationID(): ");
                close(sd);
                return 0;
            }
            std::cout << "SCTP association ID: " << assoc_id << std::endl;

            r = RecvSCTPOneToManyMessage(sd, &peer_addr,  received_string);
            if (r == -1) {
              perror("main(): recvfrom()");
              close(sd);
              return 0;
            }

            std::cout << "Received reversed string: " << received_string << std::endl;

            close(sd);
        }
    }
    return 0;
}

int Usage(char *argv[]){
  printf("\n[main] : syntax error !\n");
    printf("\nSYNTAX: %s \n"
    "-h <server IPv4 address>\n"
    "-p <listening port of server>\n"
    "-s <string to send>\n"
    "\n", argv[0]);
    return 0;
}
