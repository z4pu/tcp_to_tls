#ifndef COMMON_HPP
#define COMMON_HPP

#define MAX_STRING_LENGTH 144
#define DEBUG
#define NUM_CLIENTS 1
#define TIMEOUT_IN_SECS 10

void *get_in_addr(struct sockaddr *sa);
bool FileExists(const char* filename);

void ReverseString(char *s);

void BuildAddress(struct sockaddr_in &addr, const int &port, const char* ip);

#endif /* COMMON_HPP */
