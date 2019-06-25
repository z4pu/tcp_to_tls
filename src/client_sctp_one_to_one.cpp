
#include "common.hpp"
#include "common_sctp.hpp"
#include "client_sctp_helper_one_to_one.hpp"


#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <iostream>

extern "C" {
    #include <unistd.h>
    #include <netinet/sctp.h>
}


int Usage(char *argv[]);


int main(int argc, char *argv[]){
    int srv_port, sd, r = 0;
    unsigned char received_string[MAX_STRING_LENGTH+1] = {};

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

            if ((sd = SCTPConnectOneToOne(srv_port, argv[2])) < 0){
                perror("main(): SCTPConnect()");
                return 0;
            }

            // Send data
            r = SendSCTPOneToOne(sd, argv[6]);
            if (r == -1) {
              perror("main(): SendSCTPOneToOne()");
              close(sd);
              return 0;
            }

            r = RecvSCTPOneToOne(sd, received_string);
            if (r == -1) {
              perror("main(): ReceiveMessage()");
              close(sd);
              return 0;
            }

            std::cout << "Reversed string: " << received_string << std::endl;

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
