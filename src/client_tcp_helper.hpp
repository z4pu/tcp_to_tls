#ifndef CLIENT_TCP_HELPER_HPP
#define CLIENT_TCP_HELPER_HPP

int TCPConnect(const int& port, const char * addr);

int SendTCPRequest(const int& socket, const char * string);


#endif /* CLIENT_SCTP_HELPER_HPP */
