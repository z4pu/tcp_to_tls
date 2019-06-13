#ifndef SERVER_SCTP_HELPER_ONE_TO_MANY_HPP
#define SERVER_SCTP_HELPER_ONE_TO_MANY_HPP



int SCTPListenOneToMany(const int& port, const int& backlog);

void ProcessSCTPClientWithServerSocket (const int& server_sd);


#endif /* SERVER_SCTP_HELPER_ONE_TO_MANY_HPP */
