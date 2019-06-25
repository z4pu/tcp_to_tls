#ifndef COMMON_SCTP_HPP
#define COMMON_SCTP_HPP

extern "C" {
    #include <cstddef>
}

int RecvSCTPOneToOne(const int& socket, unsigned char * const inbuff);

int SendSCTPOneToOne(const int& socket, const char * string);
int enable_notifications(int fd);
int handle_notification(union sctp_notification *notif, size_t notif_len);
int RecvSCTPOneToManyMessage(
    int server_fd, struct sockaddr_in* sender_addr, char * inbuff);
int SendSCTPOneToManyMessage(
    int server_fd, struct sockaddr_in* dest_addr, char * outbuff);



#endif /* COMMON_SCTP_HPP */
