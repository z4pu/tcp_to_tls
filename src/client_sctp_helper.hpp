#ifndef CLIENT_SCTP_HELPER_HPP
#define CLIENT_SCTP_HELPER_HPP

int SCTPConnectOneToOne(const int& port, const char * addr);

int SCTPConnectManyToOne(const int& port, const char * addr);



#endif /* CLIENT_TCP_HELPER_HPP */
