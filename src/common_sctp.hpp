#ifndef COMMON_SCTP_HPP
#define COMMON_SCTP_HPP



int RecvSCTP(const int& socket, unsigned char * const inbuff);

int SendSCTP(const int& socket, const char * string);




#endif /* COMMON_SCTP_HPP */
