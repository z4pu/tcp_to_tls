#include "thread_helper.hpp"

#include <cstdio>
#include <cstdlib>

extern "C" {
    #include <signal.h>
}

/**
* @brief Catches SIGINT to end multithreaded server
* @param [in] arg Only 'nullptr' is used.
* @return nullptr
*/
void * SignalCatcher(void * arg)
{
	sigset_t sigset ;
	//int status;
	int sig;

	(void)arg;

	// pthread_mutex_t sig_mutex = PTHREAD_MUTEX_INITIALIZER;
	// pthread_cond_t sig_cond = PTHREAD_COND_INITIALIZER;
	// int sig_count = 0;

	/* Signalmask initialise */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);

	for (;;){
		sigwait(&sigset, &sig);
		if (sig == SIGINT){
			printf ( "Ctrl-C caught\n");
			return((void*)NULL);
		}
	}
}
