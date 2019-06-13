#ifndef SERVER_SCTP_HELPER_ONE_TO_ONE_HPP
#define SERVER_SCTP_HELPER_ONE_TO_ONE_HPP



int SCTPListenOneToOne(const int& port, const int& backlog);

void ProcessSCTPClientWithClientSocket (const int& client_sd);



#endif /* SERVER_SCTP_HELPER_ONE_TO_ONE_HPP */
