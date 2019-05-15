#include "common_tls.hpp"
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

extern "C" {
    #include <openssl/err.h>
    #include <openssl/x509v3.h>
    #include <openssl/x509.h>
}



/**
* @brief Prints to screen our own error messages and those from OpenSSL and the system.
* @param string Our error message
* @return int type with value 0
*/
int OSSLErrorHandler(const char * string)
{
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  perror(string);
  return(0);
}

int SSLReadWriteErrorHandler(SSL* ssl, int readwritten)
{
  char buf[480]={};
  unsigned long e;
  int r = SSL_get_error(ssl, readwritten);
  switch (r)
  {
    case SSL_ERROR_SSL:     {
        perror("SSL protocol error, connection failed");
        e = ERR_get_error();
        while (e != 0)      {
            ERR_error_string(e, buf);
            perror(buf);
            e = ERR_get_error();
        }
        return r;
    }

    case SSL_ERROR_SYSCALL:    {
        perror("I/O error; check sock_err");
        e = ERR_get_error();
        while (e != 0)      {
            ERR_error_string(e, buf);
            perror(buf);
            e = ERR_get_error();
        }
        return r;
    }
    case SSL_ERROR_ZERO_RETURN:    {
        perror("Connection shut down remotely");
        e = ERR_get_error();
        while (e != 0)       {
            ERR_error_string(e, buf);
            perror(buf);
            e = ERR_get_error();
        }
        return r;
    }
    default:    {
      perror("SSL read problem");
      e = ERR_get_error();
      while (e != 0)      {
          ERR_error_string(e, buf);
          perror(buf);
          e = ERR_get_error();
      }
      break;
    }
  }/*end switch*/
  return 0;
}

/**
* @brief Sets the curve parameters for ECDH during TLS to NID_X9_62_prime256v1
* @param [in] c Pointer to global SSL_CTX
* @return Modified pointer to global SSL_CTX
*/

SSL_CTX * LoadECParamsInContext(SSL_CTX *c)
{
  EC_KEY *ecdh;
  if (!c){
    return nullptr;
  }
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ecdh == NULL) /* error */
    OSSLErrorHandler("LoadECParamsInContext(): EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)");
  if(SSL_CTX_set_tmp_ecdh(c,ecdh)<0)
    OSSLErrorHandler("LoadECParamsInContext(): SSL_CTX_set_tmp_ecdh()");

  if (ecdh) EC_KEY_free(ecdh);
  return c;
}


int ReceiveSizeOfIncomingMessageTLS(SSL* const ssl) {
    uint16_t msg_length_network_order = 0;
	uint16_t msg_length_host_order = 0;
    int r = 0;

    r = SSL_read(ssl, &msg_length_network_order, 2);
    if (r < 2){
        OSSLErrorHandler("ReceiveSizeOfIncomingMessageTLS() : SSL_read()");
		return -1;
    }
	msg_length_host_order = ntohs(msg_length_network_order);

    #ifdef DEBUG
        std::cout <<  "--> ReceiveSizeOfIncomingMessageTLS(): "
            << msg_length_host_order << std::endl;
    #endif
    return msg_length_host_order;
}


int SendStringSizeTLS(SSL* const ssl, const char * string_to_send) {
    int r = 0;
    size_t length = 0;
    uint16_t size_host, size_network = 0;

    if (!ssl){
        std::cerr << "SendStringSizeTLS(): No TLS connection\n";
        return -1;
    }

    length = strlen(string_to_send);
    if (length > MAX_STRING_LENGTH-1){
        perror("SendStringSizeTLS(): Message too long");
        return -1;
    }
    size_host = (uint16_t)(length);
    size_network = htons(size_host);

    r = SSL_write(ssl, &size_network, 2);
    if (r < 2){
        OSSLErrorHandler("SendStringSizeTLS(): SSL_write()");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "--> Sent size of message " << size_host << " bytes to TLS peer!"<< std::endl;
    #endif
    return size_host;
}


int SendStringTLS(SSL* const ssl, const char * string) {
    int r = 0;
    size_t length = 0;

    if (!string){
        std::cerr << "SendStringTLS(): !string" << std::endl;
        return -1;
    }

    if (!ssl){
        std::cerr << "SendStringTLS(): No ssl" << std::endl;
        return -1;
    }

    length = strlen(string);
    if (length > MAX_STRING_LENGTH-1){
        perror("SendStringTLS(): Message too long");
        return -1;
    }

    r = SSL_write(ssl, string, (int)(length));
    if (r != (int)(length)){
        OSSLErrorHandler("SendStringTLS(): SSL_write(string)");
        return -1;
    }

    #ifdef DEBUG
        std::cout << "   -->SendStringTLS(): OK! "
        << string << std::endl;
    #endif

    return 0;
}


int ReceiveMessageTLS(SSL* const ssl, unsigned char * const inbuff) {
    int string_length, r, bytes_received  = 0;

    r = ReceiveSizeOfIncomingMessageTLS(ssl);
    if (r == -1){
    	 perror("ReceiveMessageTLS(): ReceiveSizeOfIncomingMessageTLS()");
    	return -1;
    }
    string_length = r;


    if (string_length > (MAX_STRING_LENGTH-1)){
        std::cerr << "ReceiveMessageTLS(): Message is too big" << std::endl;
        return -1;
    }

    r = SSL_read(ssl, inbuff, string_length);
    if (r != string_length){
        OSSLErrorHandler("ReceiveMessageTLS(): SSL_read(string)");
        return -1;
    }
	bytes_received = r;

    #ifdef DEBUG
        std::cout <<  "--> ReceiveMessageTLS(): bytes received = "
            << bytes_received << " containing " << inbuff << std::endl;
    #endif

    return bytes_received;
}
