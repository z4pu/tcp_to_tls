
#include "common.hpp"
#include "client_tcp_helper.hpp"


#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <cstdint>
#include <iostream>

extern "C" {
    #include <unistd.h>
}


int Usage(char *argv[]);
void ShowOptions(void);

int main(int argc, char *argv[]){
    int srv_port, sd, r = 0;
    unsigned char received_string[MAX_STRING_LENGTH] = {};

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

            if ((sd = TCPConnect(srv_port, argv[2])) < 0){
                perror("main(): TCPConnect()");
                return 0;
            }

            // Send data
            r = SendRequest(sd, argv[6]);
            if (r == -1) {
              perror("main(): SendRequest()");
              close(sd);
              return 0;
            }

            r = ReceiveMessage(sd, received_string);
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
