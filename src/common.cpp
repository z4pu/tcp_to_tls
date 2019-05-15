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

/**
* @brief Calls recv() in a loop to ensure that size bytes are read into a buffer
* @param [in] fd file descriptor of connected socket
* @param [in] size number of bytes to read from socket into buffer
* @param [in] buf starting address of buffer
* @return -1 if error, number of bytes received if successful
*/
int ReceiveNBytes(const int &fd, const int & size, unsigned char* buf)
{
     int bytesLeft = size;
     int numRd = 0;

     while (bytesLeft != 0) {
        #ifdef DEBUG
        fprintf(stderr, "reading %d bytes\n", bytesLeft);
        #endif

        /* Replacing MSG_WAITALL with 0 works fine */
        int num = recv(fd, buf, bytesLeft, MSG_WAITALL);

        if (num == 0) {
            continue;
        }
        else if (num < 0 && errno != EINTR) {
            fprintf(stderr, "ReceiveNBytes(): %d\n", __LINE__);
            return -1;
        }
        else if (num > 0) {
            numRd += num;
            buf += num;
            bytesLeft -= num;
            //fprintf(stderr, "ReceiveNBytes(): read %d bytes - remaining = %d\n", num, bytesLeft);
        }
		else{
			continue;
		}
    }
    #ifdef DEBUG
    fprintf(stderr, "--> ReceiveNBytes(): read total of %d bytes\n", numRd);
    #endif
    return numRd;
}

/**
* @brief Calls send() in a loop to ensure that size bytes are copied from buffer and written to a connected socket.
* @param [in] fd file descriptor of connected socket
* @param [in] size number of bytes to write to socket from buffer
* @param [in] buf starting address of buffer
* @return -1 if error, number of bytes sent if successful
*/
int SendNBytes(const int &fd, const int & size, unsigned char* buf)
{
     int bytesLeft = size;
     int numWr = 0;

     while (bytesLeft != 0) {
         #ifdef DEBUG
        fprintf(stderr, "reading %d bytes\n", bytesLeft);
        #endif

        /* Replacing MSG_WAITALL with 0 works fine */
        int num = send(fd, buf, bytesLeft, 0);

        if (num == 0) {
            continue;
        }
        else if (num < 0 && errno != EINTR) {
            fprintf(stderr, "SendNBytes(): %d\n", __LINE__);
            return -1;
        }
        else if (num > 0) {
            numWr += num;
            buf += num;
            bytesLeft -= num;
            //fprintf(stderr, "ReceiveNBytes(): read %d bytes - remaining = %d\n", num, bytesLeft);
        }
		else{
			continue;
		}
    }
    #ifdef DEBUG
    fprintf(stderr, "--> ReceiveNBytes(): read total of %d bytes\n", numWr);
    #endif
    return numWr;
}


/**
* @brief Receives size of incoming message from a connected socket
* @param [in] socket File descriptor of connected socket
* @return -1 if error, file size if successful
*/
int ReceiveSizeOfIncomingMessage(const int& socket){

    int r, string_size = 0;
    uint16_t size_host, size_network = 0;

	r = ReceiveNBytes(socket, sizeof(uint16_t), (unsigned char*)(&size_network));
    if (r == -1){
        std::cerr << "ReceiveSizeOfIncomingMessage(): ReceiveNBytes()" << std::endl;
        return -1;
    }

	size_host = ntohs(size_network);
	string_size = (int)(size_host);

	#ifdef DEBUG
		std::cout << "String is " << string_size << " bytes" << std::endl;
	#endif

    return string_size;
}

/**
* @brief Sends the length of a string over a connected socket.
* @param [in] socket File descriptor of connected socket
* @param [in] string_to_send string to send
* @return -1 if error, file size if successful
*/
int SendStringSize(const int& socket, const char * string_to_send){

    int r = 0;
    size_t length = 0;
    uint16_t size_host, size_network = 0;

    if (!socket){
        std::cerr << "SendStringSize(): No socket\n";
        return -1;
    }

    length = strlen(string_to_send);
    if (length > MAX_STRING_LENGTH-1){
        perror("SendStringSize(): Message too long");
        return -1;
    }
    size_host = (uint16_t)(length);
    size_network = htons(size_host);

    r = SendNBytes(socket, sizeof(uint16_t), (unsigned char*)(&size_network));
    if (r == -1){
        perror("SendStringSize(): send(filesize)");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "--> Sent size of string " << size_host << " bytes to peer!"<< std::endl;
    #endif
    return size_host;
}

/**
* @brief Sends a string over a connected socket.
* @param [in] socket File descriptor of connected socket
* @param [in] string string to send
* @return -1 if error, string size if successful
*/
int SendString(const int& socket, const char * string){
    int r = 0;
    size_t length = 0;

    if (!string){
        std::cerr << "SendString(): !string" << std::endl;
        return -1;
    }

    if (!socket){
        std::cerr << "SendString(): No socket" << std::endl;
        return -1;
    }

    length = strlen(string);
    if (length > MAX_STRING_LENGTH-1){
        perror("SendString(): Message too long");
        return -1;
    }

    r = SendNBytes(socket, (int)(length), reinterpret_cast<unsigned char*>(const_cast<char*>(string)));
    if (r == -1){
        perror("SendString(): SendNBytes(string)");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "   -->SendString(): OK!" << std::endl;
    #endif

    return 0;
}

int ReceiveMessage(const int& socket, unsigned char * const inbuff) {
    int string_length, r, bytes_received  = 0;

    r = ReceiveSizeOfIncomingMessage(socket);
    if (r == -1){
    	 perror("ReceiveMessage(): ReceiveSizeOfIncomingMessage()");
    	return -1;
    }
    string_length = r;


    if (string_length > (MAX_STRING_LENGTH-1)){
        std::cerr << "ReceiveMessage(): Message is too big" << std::endl;
        return -1;
    }

    r = ReceiveNBytes(socket, string_length, inbuff);
    if (r == -1){
        std::cerr << "ReceiveMessage(): ReceiveNBytes()" << std::endl;
        return -1;
    }
	bytes_received = r;

    return bytes_received;
}
