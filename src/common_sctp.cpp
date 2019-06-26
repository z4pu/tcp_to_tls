#include "common_sctp.hpp"
#include "common.hpp"

#include <cerrno>
#include <cstdio>
#include <iostream>

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
    #include <netinet/sctp.h>
}

/**
* @brief Receives an SCTP message
* @param [in] socket SCTP socket file descriptor
* @param [in] inbuff pointer to the start of a buffer that will contain the message
* @return -1 if error, the length of the message if successful
*/
int RecvSCTPOneToOne(const int& socket, unsigned char * const inbuff) {
    int r  = 0;

    r = recv(socket, inbuff, MAX_STRING_LENGTH, 0);
    if (r == -1){
        perror("RecvSCTPOneToOne(): recv()");
        return -1;
    }
    #ifdef DEBUG
        std::cout << "--> RecvSCTPOneToOne(): " << inbuff << std::endl;
    #endif
    return r;
}

int SendSCTPOneToOne(const int& socket, const char * string)
{
    int r = 0;

    r = send(socket, string, strlen(string), 0);
    if (r == -1){
        perror("SendSCTPOneToOne(): send()");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "--> SendSCTPOneToOne(): " << string << std::endl;
    #endif
    return 0;
}

int RecvSCTPOneToManyMessage(int server_fd, struct sockaddr_in* sender_addr,  char * inbuff)
{
    char payload[SCTP_MSG_BUFSIZE+1];
    int buffer_len = sizeof(payload) - 1;
    memset(&payload, 0, sizeof(payload));

    struct iovec io_buf;
    io_buf.iov_base = payload;
    io_buf.iov_len = buffer_len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = &io_buf;
    msg.msg_iovlen = 1;
    msg.msg_name = sender_addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);
    int recv_size = 0;

    while(1) {
        recv_size = 0;
        if((recv_size = recvmsg(server_fd, &msg, 0)) == -1) {
            printf("recvmsg() error\n");
            return -1;
        }
        strncpy(inbuff, payload, strlen(payload));

        if(msg.msg_flags & MSG_NOTIFICATION) {
            if(!(msg.msg_flags & MSG_EOR)) {
                printf("Notification received, but the buffer is not big enough.\n");
                continue;
            }

            handle_notification((union sctp_notification*)payload, recv_size);
        }
        else if(msg.msg_flags & MSG_EOR) {

            printf("RecvSCTPOneToManyMessage(): %s\n", payload);
            break;
        }
        else {
            printf("RecvSCTPOneToManyMessage(): %s", payload); //if EOR flag is not set, the buffer is not big enough for the whole message
        }
    }

    return recv_size;
}

int SendSCTPOneToManyMessage(int server_fd, struct sockaddr_in* dest_addr, char * outbuff)

{
    char buf[SCTP_MSG_BUFSIZE+1];
    memset(buf, 0, sizeof(buf));
    if (strlen(outbuff) > SCTP_MSG_BUFSIZE-1) {
        printf("SendSCTPOneToManyMessage(): Outbuff too long\n");
        return -1;
    }

    strncpy(buf, outbuff, strlen(outbuff));
    ssize_t bytes_sent = 0;

    struct iovec io_buf;
    io_buf.iov_base = buf;
    io_buf.iov_len = strlen(outbuff);

    struct msghdr msg;
    memset(&msg, 0, sizeof(struct msghdr));
    msg.msg_iov = &io_buf;
    msg.msg_iovlen = 1;
    msg.msg_name = dest_addr;
    msg.msg_namelen = sizeof(struct sockaddr_in);

    bytes_sent = sendmsg(server_fd, &msg, 0);
    if(bytes_sent == -1) {
        printf("sendmsg() error\n");
        return -1;
    }

    std::cout << "SendSCTPOneToManyMessage(): " << bytes_sent << " bytes sent\n" ;
    return bytes_sent;
}

// Source: https://github.com/tdimitrov/sctp-sandbox/blob/one-to-many_noitf/common.h
// https://petanode.com/blog/posts/sctp-notifications-in-linux.html
int enable_notifications(int fd)
{
    struct sctp_event_subscribe events_subscr;
    memset(&events_subscr, 0, sizeof(events_subscr));
    int r = 0;

    events_subscr.sctp_association_event = 1;
    events_subscr.sctp_shutdown_event = 1;

    r = setsockopt (fd, SOL_SCTP, SCTP_EVENTS, &events_subscr, sizeof(events_subscr));
    if (r == -1) {
        perror("enable_notifications(): setsockopt()");
        return -1;
    }
    return r;
}

// Source: https://github.com/tdimitrov/sctp-sandbox/blob/one-to-many_noitf/common.h
// https://petanode.com/blog/posts/sctp-notifications-in-linux.html
int handle_notification(union sctp_notification *notif, size_t notif_len)
{
    // http://stackoverflow.com/questions/20679070/how-does-one-determine-the-size-of-an-unnamed-struct
    int notif_header_size = sizeof( ((union sctp_notification*)NULL)->sn_header );

    if(notif_header_size > (int)notif_len) {
        printf("CLIENT TID %lu: Error: Notification msg size is smaller than notification header size!\n", (unsigned long)pthread_self());
        return 1;
    }

    switch(notif->sn_header.sn_type) {
    case SCTP_ASSOC_CHANGE: {
        if(sizeof(struct sctp_assoc_change) > notif_len) {
            printf("CLIENT TID %lu: Error: Notification msg size is smaller than struct sctp_assoc_change size\n", (unsigned long)pthread_self());
            return 2;
        }

        char* state = NULL;
        struct sctp_assoc_change* n = &notif->sn_assoc_change;

        switch(n->sac_state) {
        case SCTP_COMM_UP:
            state = const_cast<char*>("COMM UP");
            break;

        case SCTP_COMM_LOST:
            state = const_cast<char*>("COMM_LOST");
            break;

        case SCTP_RESTART:
            state = const_cast<char*>("RESTART");
            break;

        case SCTP_SHUTDOWN_COMP:
            state = const_cast<char*>("SHUTDOWN_COMP");
            break;

        case SCTP_CANT_STR_ASSOC:
            state = const_cast<char*>("CAN'T START ASSOC");
            break;
        }

        printf("CLIENT TID %lu: SCTP_ASSOC_CHANGE notif: state: %s, error code: %d, out streams: %d, in streams: %d, assoc id: %d\n",
            (unsigned long)pthread_self(),
            state, n->sac_error, n->sac_outbound_streams, n->sac_inbound_streams, n->sac_assoc_id);

        break;
    }

    case SCTP_SHUTDOWN_EVENT: {
        if(sizeof(struct sctp_shutdown_event) > notif_len) {
            printf("CLIENT TID %lu: Error notification msg size is smaller than struct sctp_assoc_change size\n", (unsigned long)pthread_self());
            return 3;
        }

        struct sctp_shutdown_event* n = &notif->sn_shutdown_event;

        printf("CLIENT TID %lu: SCTP_SHUTDOWN_EVENT notif: assoc id: %d\n",
        (unsigned long)pthread_self(), n->sse_assoc_id);
        break;
    }

    default:
        printf("CLIENT TID %lu: Unhandled notification type %d\n",
        (unsigned long)pthread_self(),
        notif->sn_header.sn_type);
        break;
    }

    return 0;
}

// Source: https://www.linuxjournal.com/article/9784
int GetSCTPAssociationID(int sockfd, struct sockaddr *sa, socklen_t salen) {
    struct sctp_paddrinfo sp;
    int sz, r;

    sz = sizeof(struct sctp_paddrinfo);
    bzero(&sp, sz);
    memcpy(&sp.spinfo_address, sa, salen);
    r = sctp_opt_info(sockfd, 0, SCTP_GET_PEER_ADDR_INFO, &sp, (socklen_t*)&sz);
    if (r == -1) {
        perror("GetSCTPAssociationID(): sctp_opt_info");
        return -1;
    }
    return (sp.spinfo_assoc_id);
}
