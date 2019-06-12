#ifndef SERVER_SCTP_HELPER_HPP
#define SERVER_SCTP_HELPER_HPP



int SCTPListenOneToOne(const int& port, const int& backlog);

int SCTPListenOneToMany(const int& port, const int& backlog);

void ProcessSCTPClientWithClientSocket (const int& client_sd);
void ProcessSCTPClientWithServerSocket (const int& server_sd);


#endif /* SERVER_SCTP_HELPER_HPP */
