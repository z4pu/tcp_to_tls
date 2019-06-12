#ifndef SERVER_TCP_HELPER_HPP
#define SERVER_TCP_HELPER_HPP


int TCPListen(const int& port, const int& backlog);


void ProcessTCPClient (const int& client_sd);



#endif /* SERVER_TCP_HELPER_HPP */
