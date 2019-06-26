#include "server_sctp_helper_one_to_one.hpp"
#include "common.hpp"
#include "thread_helper.hpp"
#include "thread_sctp_helper_one_to_one.hpp"

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
    #include "pthread_wrap.h"
}

extern "C" {
    #include <unistd.h>
}

extern "C" {
    #include <signal.h>
    #include <pthread.h>
}



pthread_mutex_t sd_mutex;

int Usage(int err, char *argv[]);


int main(int argc, char *argv[])
{
    int err = 0;
    int sd, server_port, status = 0;
    tcp_client_thread_args args;
    sigset_t sigset;
    pthread_t tid[MAX_CLIENTS] = {};

    memset(&args, 0, sizeof(args));

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


    mutexInit(&sd_mutex, NULL);

    /* Signalmask initialise */
    /* Block SIGPIPE; other threads created by main()
    will inherit a copy of the signal mask. */
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGPIPE);

    /* Set Signalmask for main () - Thread*/
    status = pthread_sigmask(SIG_BLOCK, &sigset, NULL);
    if (status != 0)  {
        fprintf(stderr, "pthread_sigmask() failed : %s", strerror(status));
        close (sd); /* Close passive Socket*/
        goto end;
    }

    for (int i=0; i < MAX_CLIENTS; i++ ) {
        /* Start accept_handler (SIGTERM blocked) */
        args.server_sd = sd;
        args.connection_number = i+1;

        status = pthread_create(&tid[i], NULL, SCTPClientOneToOneThread, (void *)&args);
        if (status != 0)    {
            printf("pthread_create() failed : %s\n", strerror(status));
            close(sd); /* passive Socket closed */
            goto end;
        }
    }
    SignalCatcher(nullptr); /* Main thread handles signal */

    end:
    std::cout << "Shutting down server" << std::endl;

    for (int i = 0; i < MAX_CLIENTS; i++ ){
        status = pthread_cancel(tid[i]);
        std::cout << "Tried to cancel "<< tid[i] << std::endl;
        if (status != 0)  {
            fprintf(stderr, "pthread_cancel() failed : %s\n", strerror(status));
        }
        status = pthread_join(tid[i], nullptr);
        std::cout << "Tried to join "<< tid[i] << std::endl;
        if (status != 0)  {
            fprintf(stderr, "pthread_join() failed : %s\n", strerror(status));
        }
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
