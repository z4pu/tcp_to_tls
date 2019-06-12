#ifndef COMMON_TCP_HPP
#define COMMON_TCP_HPP



int ReceiveNBytes(const int &fd, const int & size, unsigned char* buf);

int SendNBytes(const int &fd, const int & size, unsigned char* buf);

int ReceiveSizeOfIncomingMessage(const int& socket);

int SendStringSize(const int& socket, const char * string_to_send);

int SendString(const int& socket, const char * string);

int ReceiveMessage(const int& socket, unsigned char * const inbuff);

#endif /* COMMON_TCP_HPP */
