#ifndef SERVER_TCP_HELPER_HPP
#define SERVER_TCP_HELPER_HPP

#define NUM_CLIENTS 1
#define TIMEOUT_IN_SECS 10

int TCPListen(const int& port, const int& backlog);


void ProcessClient (const int& client_sd);

void ReverseString(char *s);

#endif /* SERVER_TCP_HELPER_HPP */
