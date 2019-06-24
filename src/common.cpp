#include "common.hpp"

#include <cerrno>
#include <cstdio>
#include <iostream>

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
    #include <unistd.h>
}

void *get_in_addr(struct sockaddr *sa) {
  return sa->sa_family == AF_INET
    ? (void *) &(((struct sockaddr_in*)sa)->sin_addr)
    : (void *) &(((struct sockaddr_in6*)sa)->sin6_addr);
}

/**
* @brief Check that file exists and can be read
* @param [in] filename Filename
* @return TRUE if true, FALSE otherwise
*/
bool FileExists(const char* filename)
{
    if (FILE *file = fopen(filename, "r")) {
        fclose(file);
        return true;
    } else {
        std::cerr << "!FileExists()\n";
        return false;
    }
}

void ReverseString(char *s)
{
	int i, j;
	char c;
    sleep(10);
	j = strlen(s);
	for (i=0, j = strlen(s)-1; i<j; i++, j--)
	{
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

void BuildAddress(struct sockaddr_in &addr, const int &port, const char* ip)
{
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  inet_aton(ip, &addr.sin_addr);
}
