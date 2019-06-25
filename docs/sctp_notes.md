Source: <https://www.linuxjournal.com/article/9748>


# Introduction to Stream Control Transmission Protocol
by Jan Newmarch
on September 1, 2007

Most people who have written networking software are familiar with the TCP and UDP protocols. These are used to connect distributed applications and allow messages to flow between them. These protocols have been used successfully to build Internet applications as we know them: e-mail, HTTP, name services and so forth. But, these protocols are more than 20 years old, and over time, some of their deficiencies have become well known. Although there have been many attempts to devise new general-purpose transport protocols above the IP layer, only one so far has received the blessing of the IETF: SCTP (Stream Control Transmission Protocol). The central motivation behind SCTP is to provide a more reliable and robust protocol than either TCP or UDP that can take advantage of features such as multihoming.

SCTP is not a radical departure from TCP or UDP. It borrows from both but is most similar to TCP. It is a reliable session-oriented protocol, like TCP. It adds new features and options and allows finer control over the transport of packets. In all but the “edge” cases, it can be used as a drop-in in place of TCP. This means that TCP applications often can be ported trivially to SCTP. Of course, to benefit properly from the new features of SCTP, you need to use the additional API calls for SCTP.

The first additional feature in SCTP is better support for multihomed devices—that is, computers with more than one network interface. At one time this meant only routers and bridges connecting different parts of the Internet, but now even computers on the edges of the network can be multihomed. Most laptops have built-in Ethernet cards and Wi-Fi cards, and many have Bluetooth cards as well (which have IP support through the Bluetooth PPP stack). Some laptops now are shipping with WiMAX cards, and it even is possible to run IP over the infrared port! So, the standard laptop is at least dual-homed, with possibly up to five distinct IP network interfaces.

TCP and UDP allow use of only one or all of the interfaces. But, what if you are running your laptop as a peer in, say, a file-sharing service? It probably would be silly to use the Bluetooth and infrared interfaces. WiMAX can be very expensive to shift large amounts of data. But, it would make sense to use both the Ethernet and Wi-Fi interfaces. SCTP can support this selective choosing of interfaces. Some implementations even can add and drop interfaces dynamically, so as you unplug your laptop and move out of the house, an application can switch to the WiMAX interface if you want.

The second main new feature is multistreaming—that is, one “association” (which is renamed from “connection” from TCP) can support multiple data streams. It is no longer necessary to open up multiple sockets; instead, a single socket can be used for multiple streams to a connected host. Several TCP applications could benefit from this. For example, FTP (the major file transfer protocol) uses two streams: one on port 21 for control messages and another on port 20 for data. This caused problems with firewalls in place. A client could connect to a server through a firewall, but the server could not connect to the client for data transfer because of the firewall. The FTP protocol had to be extended to allow for “passive” connections to overcome this. There would be no need for such an extension under SCTP—simply send the data on a separate stream in an association established by a client.

The X Window System also uses multiple sockets on multiple ports. Although it is not common, a computer can have multiple display devices. Typically, the first is on port 6000, the second on port 6001 and so on. Under SCTP, these could all be separate streams on a single association. HTML documents often contain embedded references to image files, and to display a page properly requires downloading the original page and all of these images (or embedded frames too). HTTP originally used a separate TCP connection per downloaded URL, which was expensive and time consuming. HTTP 1.1 brought in “persistent connections”, so that a single socket could be reused for all of these sequential downloads. Under SCTP, the separate images could be downloaded concurrently in separate streams on a single association.

There are even more subtle uses of SCTP multiple streams. An MPEG movie consists of different types of frames: I frames, P frames and B frames. I frames encode complete images, and the other two types measure differences between frames. Typically, there is an I frame every ten frames, with the others “predicted” from these. It is critical that the I frames be delivered, but less so for the P and B frames. Although SCTP is not designed as a Quality-of-Service protocol, it does allow different delivery parameters on different streams within an association, so that the I frames can be delivered more reliably.

SCTP has many more features, such as:

-    TCP is a byte-oriented protocol, and UDP is message-oriented. The majority of applications are message-oriented, and applications using TCP have to jump through hoops, such as sending the message length as a first parameter. SCTP is message-oriented, so such tricks are not so necessary.

-    A single socket can support multiple associations—that is, a computer can use a single socket to talk to more than one computer. This is not multicast, but it could be useful in peer-to-peer situations.

-    SCTP has no “out of band” messages, but a large number of events can be interleaved onto a single association, so that an application can monitor the state of the association (for example, when the other end adds another interface to the association).

-    The range of socket options is greater than TCP or UDP. These also can be used to control individual associations or individual streams within a single association. For example, messages on one stream can be given a longer time-to-live than messages on other streams, increasing the likelihood of their delivery.

## Availability of SCTP

The SCTP Web site (www.sctp.org) has a list of implementations of SCTP. There are implementations for BSD and Windows, and since 2001, there has been a Linux kernel project at sourceforge.net/projects/lksctp. At present, SCTP is not in any Microsoft release, so applications running on Windows need to install one of the available stacks.

SCTP is included in the Linux kernel as an experimental network protocol. SCTP is normally built as a module. It may be necessary to load the module using modprobe sctp. To build user applications, you may need to install the SCTP tools—in Fedora Core 6, these are in the RPM packages lksctp-tools-1.0.6-1.fc6.i386.rpm and lksctp-tools-devel-1.0.6-1.fc6.i386.rpm. On Fedora Core 6, I also had to add a symbolic link from /usr/lib/libsctp.so to /usr/lib/libsctp.so.1.

The lksctp-tools package contains the libraries to run SCTP applications. It also contains a program called checksctp, which tells you if your kernel has support for SCTP. When you run this program, it prints either “SCTP supported” or an error message.

The devel package contains the sctp.h header file, so you can compile and build your own applications, and man pages for the SCTP function calls.
Firewalls

Most firewalls can be configured to deal with SCTP packets, but the documentation for each firewall may not mention SCTP explicitly. For example, the man page for iptables says, “The specified protocol [in a rule] can be one of tcp, udp, icmp, or all...”. But, it then goes on to say, “A protocol name from /etc/protocols is also allowed”, and in that file, we find that protocol 132 is sctp. So, rules for SCTP can be added to iptables in the same way as TCP and UDP rules.

For example, an iptables rule to accept SCTP connections to port 13 would be:

```
-A INPUT -p sctp -m sctp -i eth0 --dport 13 -j ACCEPT
```
Webmin is a popular administration tool for managing things like iptables rules. Unfortunately, as of version 1.340, it could not accept this rule, because it is hard-wired to accept port numbers only for TCP and UDP, not realising that SCTP also uses port numbers. Such a rule would need to be entered by hand into the iptables configuration file /etc/sysconfig/iptables. This will be fixed in later versions of Webmin after I logged a bug report, but similar problems may occur in other tools.
One-to-One Socket API

As with TCP and UDP, SCTP provides a socket API for applications. A server creates a socket bound to a port and then uses this to accept a connection from a client. A client also creates a socket and then connects to a server. Both then use the socket file descriptor to read and write messages. SCTP is not a superset of TCP. Nevertheless, when restricted to a similar style of connection as TCP, there are sufficient similarities that an SCTP socket often can be used as a drop-in replacement for a TCP socket. When used in this way, SCTP sockets are called one-to-one sockets, as they simply connect one host to a single other host.

To create a TCP socket, use the system call:
```
sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
```
This creates an IPv4 socket. To create an IPv6 socket, replace the first parameter with AF_INET6. The last parameter often is given as zero, meaning “use the only protocol value in the family”. It is better to use IPPROTO_TCP explicitly, because SCTP introduces another possible value.

To create an SCTP one-to-one socket, simply replace IPPROTO_TCP with IPPROTO_SCTP:
```
sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)
```
and that (in many cases) is it! The client or server is now talking the SCTP protocol instead of TCP.

To see this in action, Listings 1 (echo_client.c) and 2 (echo_server.c) give a simple echo-client and server, where the server returns a string sent to it when a client connects to it. Only the line above needs to change in both the client and the server (with also an extra include file, sctp.h).

Listing 1. echo_client.c

```
#define USE_SCTP

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef USE_SCTP
#include <netinet/sctp.h>
#endif

#define SIZE 1024
char buf[SIZE];
char *msg = "hello\n";
#define ECHO_PORT 2013

int main(int argc, char *argv[]) {
        int sockfd;
        int nread;
        struct sockaddr_in serv_addr;
        if (argc != 2) {
                fprintf(stderr, "usage: %s IPaddr\n", argv[0]);
                exit(1);
        }
        /* create endpoint using TCP or SCTP */
        sockfd = socket(AF_INET, SOCK_STREAM,
#ifdef USE_SCTP
                        IPPROTO_SCTP
#else
                        IPPROTO_TCP
#endif
                );
        if (sockfd < 0) {
                perror("socket creation failed");
                exit(2); }
        /* connect to server */
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
        serv_addr.sin_port = htons(ECHO_PORT);
        if (connect(sockfd,
                    (struct sockaddr *) &serv_addr,
                    sizeof(serv_addr)) < 0) {
                perror("connect to server failed");
                exit(3);
        }
        /* write msg to server */
        write(sockfd, msg, strlen(msg) + 1);
        /* read the reply back */
        nread = read(sockfd, buf, SIZE);
        /* write reply to stdout */
        write(1, buf, nread);

        /* exit gracefully */
        close(sockfd);
        exit(0);
}
```
Listing 2. echo_server.c

```
#define USE_SCTP

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef USE_SCTP
#include <netinet/sctp.h>
#endif

#define SIZE 1024
char buf[SIZE];
#define ECHO_PORT 2013

int main(int argc, char *argv[]) {
        int sockfd, client_sockfd;
        int nread, len;
        struct sockaddr_in serv_addr, client_addr;

        /* create endpoint using TCP or SCTP */
        sockfd = socket(AF_INET, SOCK_STREAM,
#ifdef USE_SCTP
                        IPPROTO_SCTP
#else
                        IPPROTO_TCP
#endif
                );
        if (sockfd < 0) {
                perror("socket creation failed");
                exit(2);
        }
        /* bind address */
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(ECHO_PORT);
        if (bind(sockfd,
                 (struct sockaddr *) &serv_addr,
                 sizeof(serv_addr)) < 0) {
                perror("bind failed");
                exit(3); }
        /* specify queue length */
        listen(sockfd, 5);
        for (;;) {
                len = sizeof(client_addr);
                /* get a connection from client */
                client_sockfd = accept(sockfd,
                                       (struct sockaddr *) &client_addr,
                                       &len);
                if (client_sockfd == -1) {
                        perror("accept failed");
                        continue;
                }
                /* transfer data */
                nread = read(client_sockfd, buf, SIZE);
                /* write to stdout */
                write(1, buf, nread);
                /* and echo it back to client */
                write(client_sockfd, buf, nread);
                /* no more for this client */
                close(client_sockfd);
        }
}
```
The usual C compile command can be used to create object modules and executables. If the program uses SCTP-specific functions (the programs in Listings 1 and 2 don't), you also need to link in the SCTP library:
```
cc -o echo_client echo_client.c -lsctp
```
Is it worthwhile to take an application that runs over TCP and move it to SCTP? The disadvantages are that SCTP is not as well supported as TCP, the tools are sometimes not aware of SCTP and the API is still evolving. On the other hand, it benefits from the experience of 20 years of seeing TCP and UDP applications in practice. For example, SCTP is secure from SYN attacks by design, and the protocol has no known security holes. SCTP also will take advantage of multihoming when needed automatically. If packets are getting lost, due to, say, congestion, SCTP will use different interfaces to try to avoid the losses, and this could result in faster throughput.
The withsctp Tool

In the previous section, I discussed how to alter the source code of a client or server to use SCTP instead of TCP. The sctp-tools package contains a program called withsctp, which essentially does the same to binary code. This program acts as a wrapper around a TCP application to turn it into an SCTP application. It first saves the address of the “real” socket() function call, and then inserts its own version of socket() into the load library path. This new version of socket() simply gets the parameters of the function call, changes the third parameter from IPPROTO_TCP to IPPROTO_SCTP and calls the “real” socket() function.

For example, the xinetd dæmon can run a group of TCP and UDP services. The services are those listed in the directory /etc/xinetd.d, which have enable = yes or disable = no. The TCP services all can be run over SCTP by:
```
withsctp xinetd
```
One of the simplest services that is run by xinetd is daytime. The service accepts a connection and returns an ASCII string for the current date. A quick Google search turns up source code for many clients, but the simplest way is to run Telnet:

```
telnet <host-name> 13
```
If you have daytime running as an SCTP service rather than a TCP service, use withsctp to connect to it:

```
withsctp telnet <host-name> 13
```
This is a quick way of testing whether a TCP service can be converted to SCTP.
## Message Orientation

TCP is a byte-oriented protocol—that is, you write bytes and read bytes. The UNIX system calls read() and write() typically are used for this. TCP also has send()/recv(), which have an extra flags parameter, but these do not change the byte-transfer model.

SCTP, on the other hand, is message-oriented, more like UDP. Most Internet applications have a message structure to their communications rather than merely a sequence of bytes. For example, a single HTTP request has a header and body section, and even the header section is composed of an arbitrary number of lines. The sender has to compose the parts into the single request, and the receiver of such a message has to parse it back into its component messages. A few protocols are only byte-oriented (for example, the file transfer mode of FTP), but these are the minority.

SCTP makes it easy to use a message-based structure—within limits. A write() call writes a complete message. The corresponding read() reads this complete message. So, to send an HTTP header over SCTP, you could do a write of each line, followed by a write of an empty line. The receiver would read each line as a separate message, stopping after reading an empty line. There would be no need to parse the received bytes into a set of lines before processing each one. Note that if the original TCP application already used a series of writes followed by a single read, expecting TCP to concatenate all the messages, the application would need to be modified to match each write to a corresponding read statement.

The caveats are with big messages. Applications that want to take advantage of these messaging capabilities must be careful when sending big messages (say 32KB or more). To send a message, you aren't merely passing a pointer to data on the stack, you're actually moving that data across the network. That means putting it into buffers on the sender side, passing it through buffers in intermediate nodes and, finally, delivering it to a buffer in the reading application. All of these buffers have limits that cannot be exceeded.

For example, say a sender uses a buffer with a size set by the socket option SO_SNDBUF. An attempt to write a message larger than that will fail and return -1. The size of this is generous, typically about 64KB. It can be changed by using setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &val, &val_len), where val is an integer variable containing the length to which you want to set the buffer. But, then other limits may come into play. Each host along the route from sender to receiver will have a maximum packet size that it will pass along. The Path Maximum Transmission Unit (PMTU) is the minimum of all of these. If the message (plus any IP and SCTP headers) is larger than the PMTU, it will be fragmented and delivered in pieces. The sender can guard against this by setting the SCTP option SCTP_DISABLE_FRAGMENTS so that a message is delivered as a single entity or not at all, but this typically will only decrease the maximum possible message size.

The receiver of a message also has a receiving buffer size, which is controlled by the socket option SO_RCVBUF. It will not receive messages larger than this—fragmenting them if necessary. The major problem from the receiving side is how to deal with fragmented messages. The system calls read() and recv() do not contain any information about message boundaries, as they are byte-oriented. Fortunately, SCTP has a new system call, sctp_recvmsg(), which returns status information about the read in an integer parameter. In particular, if the MSG_EOR bit (message end-of-record) is set, read of a message has been completed. If it is not set, the message has been fragmented and more of the message needs to be read. This can be used by the reader to build up a complete message before processing it.

Listing 3 shows how the sctp_recvmsg() call can be used to receive fragmented messages and build them up into a complete message. It does so by reading each part of a message as it comes in and adding it to the parts already received. When a part arrives with the MSG_EOR bit set in the flags, the message is complete and can be returned to the reading application.

Listing 3. read_sctp_msg.c

```
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <netinet/sctp.h>

/* call by
     nread = read_sctp_msg(sockfd, &msg)
*/
int read_sctp_msg(int sockfd, uint8_t **p_msg) {
        int rcv_buf_size;
        int rcv_buf_size_len = sizeof(rcv_buf_size);
        uint8_t *buf;
        struct sockaddr_in peeraddr;
        int peer_len = sizeof(peeraddr);
        struct sctp_sndrcvinfo sri;
        int total_read = 0;

        *p_msg = NULL; /* default fail value */

        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF,
                       &rcv_buf_size, &rcv_buf_size_len) == -1) {
                return -1;
        }
        if ((buf = malloc(rcv_buf_size)) == NULL) {
                return -1;
        }

        while (1) {
                int nread;
                int flags;

                nread = sctp_recvmsg(sockfd, buf+total_read,rcv_buf_size,
                                     (struct sockaddr *) &peeraddr,&peer_len,
                                     &sri, &flags);
                if (nread < 0) {
                        return nread;
                }
                total_read += nread;

                if (flags & MSG_EOR) {
                        /* trim the buf and return msg */
                        printf("Trimming buf to %d\n", total_read);
                        *p_msg = realloc(buf, total_read);
                        return total_read;
                }
                buf = realloc(buf, total_read + rcv_buf_size);
        }

        /* error to get here? */
        free(buf);
        return -1;
}
```
## IPv6

SCTP has full support out of the box for IPv6 as well as IPv4. You simply need to use IPv6 socket addresses instead of IPv4 socket addresses. If you create an IPv4 socket, SCTP will deal only with IPv4 addresses. But, if you create an IPv6 socket, SCTP will handle both IPv4 and IPv6 addresses.
## Conclusion

This article provides a brief introduction to the IETF Stream Control Transmission Protocol and explains how it can be used as a replacement for TCP. In future articles, we will examine additional features of SCTP and show their use.

## Resources

The Principal Site for SCTP (contains pointers to the RFCs and Internet Drafts for SCTP): www.sctp.org

The Linux Kernel Project Home Page: https://lists.sourceforge.net/lists/listinfo/lksctp-developers.

Stream Control Transmission Protocol (SCTP): A Reference Guide by Randall Stewart and Qiaobing Xie, Addison-Wesley.

Unix Network Programming (volume 1, 3rd ed.) by W. Richard Stevens, et al., has several chapters on SCTP, although some of it is out of date.

Jan Newmarch is Honorary Senior Research Fellow at Monash University. He has been using Linux since kernel 0.98. He has written four books and many papers and also has given courses on many technical topics, concentrating on network programming for the last six years. His Web site is jan.newmarch.name.

# One-to-one vs one-to-many

<https://docs.oracle.com/cd/E19253-01/816-5177/6mbbc4gam/index.html>


One-to-one style socket interface supports similar semantics as sockets for connection oriented protocols, such as TCP.
Thus, a passive socket is created by calling the listen(3SOCKET) function after binding the socket using bind().
Associations to this passive socket can be received using accept(3SOCKET) function.
Active sockets use the connect(3SOCKET) function after binding to initiate an association. If an active socket is not explicitly bound, an implicit binding is performed.
If an application wants to exchange data during the association setup phase, it should not call connect(), but use sendto(3SOCKET)/sendmsg(3SOCKET) to implicitly initiate an association. Once an association has been established, read(2) and write(2) can used to exchange data. Additionally, send(3SOCKET), recv(3SOCKET), sendto(), recvfrom(3SOCKET), sendmsg(), and recvmsg(3SOCKET) can be used.

One-to-many socket interface supports similar semantics as sockets for connection less protocols, such as UDP (however, unlike UDP, it does not support broadcast or multicast communications).

A passive socket is created using the listen() function after binding the socket using bind().
An accept() call is not needed to receive associations to this passive socket (in fact, an accept() on a one-to-many socket will fail).
Associations are accepted automatically and notifications of new associations are delivered in recvmsg() provided notifications are enabled.
Active sockets after binding (implicitly or explicitly) need not call connect() to establish an association, implicit associations can be created using sendmsg()/recvmsg() or sendto()/recvfrom() calls.
Such implicit associations cannot be created using send() and recv() calls. On an SCTP socket (one-to-one or one-to-many), an association may be established using sendmsg(). However, if an association already exists for the destination address specified in the msg_name member of the msg parameter, sendmsg() must include the association id in msg_iov member of the msg parameter (using sctp_sndrcvinfo structure) for a one-to-many SCTP socket. If the association id is not provided, sendmsg() fails with EADDRINUSE. On a one-to-one socket the destination information in the msg parameter is ignored for an established association.

# SCTP notifications
https://petanode.com/blog/posts/sctp-notifications-in-linux.html

Each SCTP notification that you want to receive should be explicitly enabled with socket option. There are two ways to do that but more on this in the next section. When SCTP event occurs (and you are subscribed for it) it will be delivered with recvmsg(). The MSG_NOTIFICATION flag will be set in struct msghdr's msg_flags field. As for payload data you can check if the whole notification is delivered by checking if MSG_EOR flag is set. recvmsg() will always deliver only one notification per call.
