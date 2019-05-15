#ifndef CLIENT_TCP_HELPER_HPP
#define CLIENT_TCP_HELPER_HPP

int TCPConnect(const int& port, const char * addr);

int SendRequest(const int& socket, const char * string);

int ReceiveResponse(const int& socket, const char * received_string);

#endif /* CLIENT_TCP_HELPER_HPP */
