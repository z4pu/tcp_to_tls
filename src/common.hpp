#ifndef COMMON_HPP
#define COMMON_HPP

#define MAX_STRING_LENGTH 144
#define DEBUG

void *get_in_addr(struct sockaddr *sa);

bool FileExists(const char* filename);

int ReceiveNBytes(const int &fd, const int & size, unsigned char* buf);

int SendNBytes(const int &fd, const int & size, unsigned char* buf);

int ReceiveSizeOfIncomingMessage(const int& socket);

int SendStringSize(const int& socket, const char * string_to_send);

int SendString(const int& socket, const char * string);

int ReceiveMessage(const int& socket, unsigned char * const inbuff);



#endif /* COMMON_HPP */
