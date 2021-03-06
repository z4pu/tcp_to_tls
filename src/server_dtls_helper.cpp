#include "server_dtls_helper.hpp"
#include "server_tcp_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

#include <iostream>


#include "ck_secrets_vault.h"


extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
}


/**
* @brief Initialise and populate global SSL_CTX* for DTLS connection
* @param [in] nothing
* @return -1 if error, 0 if successful
*/

SSL_CTX* DTLSInitServerContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* trusted_certs_file)
{
    int result = 0;


    // OLD OPENSSL_VERSION_NUMBER  0x1000114fL
    // 1.02 OPENSSL_VERSION_NUMBER  0x100020bfL
    // Create a new context using TLS

    ctx = SSL_CTX_new(DTLS_server_method());
    if (ctx == NULL) {
         OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_new(DTLS_server_method()): Cannot create SSL Context");
         return nullptr;
    }

    result = SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    if (result == 0) {
        OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_set_min_proto_version()");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Set our supported ciphers
    result = SSL_CTX_set_cipher_list(ctx, FULLCIPHERLIST);
    if (result != 1)    {
      OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_set_cipher_list()");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    SSL_CTX_set_default_passwd_cb(ctx, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Load the certificate file; contains also the public key
    if (!FileExists(cert_file))  {
        std:: cerr << "DTLSInitServerContextFromKeystore(): !FileExists(SERVER_CERTIFICATE)" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    result = SSL_CTX_use_certificate_file(ctx, cert_file,
            SSL_FILETYPE_PEM);
    if (result != 1)      {
      OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_use_certificate_file()");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    // Load private key
    if (!FileExists(privkey_file))  {
        std:: cerr << "DTLSInitServerContextFromKeystore(): !FileExists(SERVER_PRIVATEKEY)" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    result = SSL_CTX_use_PrivateKey_file(ctx, privkey_file, SSL_FILETYPE_PEM);
    if (result != 1)      {
      OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_use_PrivateKey_file()");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(ctx);
    if (result != 1)        {
      OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_check_private_key(ctx)");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    if (!FileExists(trusted_certs_file))  {
        std:: cerr << "DTLSInitServerContextFromKeystore(): !FileExists(trusted_certs_file)" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if(!(SSL_CTX_load_verify_locations(ctx, trusted_certs_file, nullptr)))      {
      OSSLErrorHandler("DTLSInitServerContextFromKeystore(): SSL_CTX_load_verify_locations(ctx)");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    ctx = LoadECParamsInContext(ctx);

    SSL_CTX_set_cookie_generate_cb(ctx, GenerateCookie);
    SSL_CTX_set_cookie_verify_cb(ctx, VerifyCookie);

    return ctx;
}


void ProcessDTLSClient (const int &server_fd, SSL_CTX * const ctx){
    int r, cookie_r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    std::string instring, outstring;
    BIO * dgramBio = nullptr;
    SSL * ssl = nullptr;

    BIO_ADDR* client_addr_bio = BIO_ADDR_new();
    if (!client_addr_bio) {
        OSSLErrorHandler("ProcessDTLSClient(): BIO_ADDR_new(): cannot create BIO for client address");
        return;
    }

    dgramBio = BIO_new_dgram(server_fd, BIO_NOCLOSE);
    if (!dgramBio) {
        OSSLErrorHandler("ProcessDTLSClient(): BIO_new_dgram(): cannot create from fd");
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL){
        OSSLErrorHandler("ProcessDTLSClient(): SSL_new(): ");
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    // Now SSL will apply to all data coming from the file descriptor
    // From OpenSSL 1.1.1c docs:
    // The ssl parameter should be a newly allocated SSL
    // object with its read and write BIOs set, in the same way
    // as might be done for a call to SSL_accept(). Typically,
    // for DTLS, the read BIO will be in an "unconnected"
    // state and thus capable of receiving messages from any peer.
    //void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
    // rbio is used for SSL_read, wbio is used for SSL_write
    SSL_set_bio(ssl, dgramBio, dgramBio);
    SSL_set_accept_state(ssl);

    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);


    #ifdef DEBUG
    printf("DTLS Listening ...\n");
    #endif

    do {
        cookie_r = DTLSv1_listen(ssl, client_addr_bio);
    }    while (!cookie_r);
    if (cookie_r < 0) {
        OSSLErrorHandler("ProcessDTLSClient(): DTLSv1_listen(): ");
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }
    #ifdef DEBUG
    std::cout << "Cookie exchange OK, DTLSv1_listen() returned " << cookie_r << std::endl;
    #endif

    // set BIO to connected
    if (!BIO_connect(server_fd, client_addr_bio, 0)) {
        OSSLErrorHandler("ProcessDTLSClient(): BIO_connect(): ");
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    // Attempt to complete the DTLS handshake
    // If successful, the DTLS link state is initialized internally
    #ifdef DEBUG
    std::cout << "waiting for SSL_accept() " << std::endl;
    #endif

    int acc_r = SSL_accept(ssl);
    if (acc_r <= 0)  {
        OSSLErrorHandler("ProcessDTLSClient(): SSL_accept(): ");
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }
    #ifdef DEBUG
    std::cout << "SSL_accept() ok, returned " << acc_r << std::endl;
    #endif

    r = ReceiveMessageTLS(ssl, buff);
    if (r == -1) {
        perror("ProcessTLSClient(): ReceiveMessageTLS()");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendStringSize(reversed string)");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendString(reversed string)");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        BIO_ADDR_free(client_addr_bio);
        return;
    }

    #ifdef DEBUG
        std::cout <<  "--> ProcessTLSClient(): OK, reversed string: "
        << buff << std::endl;
    #endif
    SSL_shutdown(ssl);
    SSL_free(ssl);
    BIO_ADDR_free(client_addr_bio);
    return;
}

// The content is arbitrary, but for security reasons it should contain
//the client's address, a timestamp and should be signed.
int GenerateCookie( SSL *ssl, unsigned char *cookie,
  unsigned int *cookie_len )
{

  /* Get peer information, allocate a buffer [...] */
  char *buff, result[EVP_MAX_MD_SIZE];
  unsigned int length, resultlength;

  union {
        struct sockaddr_storage sa;
        struct sockaddr_in s4;
      } peer;


  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  length += sizeof(struct in_addr);
  length += sizeof(peer.s4.sin_port);

  buff = (char*)OPENSSL_malloc(length);

  if (buff == NULL) {
        BIO_printf(bio_err, "out of memory\n");
        return 0;
    }

  memcpy(buff, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
  memcpy(buff + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
              sizeof(struct in_addr));

  /* Generate the cookie with a random secret in buff ... */
  HMAC(EVP_sha256(), ck_secrets_random(), CK_SECRET_LEN,
          (unsigned char *)buff,length,
          (unsigned char *)result, &resultlength);

  /* and copy buff to the provided *cookie memory location [...] */
  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;

    /* Clean up all the stuff [...] */
  OPENSSL_free(buff);

  return 1;
}

int VerifyCookie( SSL *ssl, const unsigned char *cookie,
    unsigned int cookie_len )
{
  /* Get peer information, allocate a buffer [...] */
  char *buff;
  unsigned int length;

  union {
        struct sockaddr_storage sa;
        struct sockaddr_in s4;
      } peer;
  /* Handle ssl & cookie stuff [......] */

  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  length += sizeof(struct in_addr);
  length += sizeof(peer.s4.sin_port);

  buff = (char*)OPENSSL_malloc(length);

  if (buff == NULL)  {
      BIO_printf(bio_err, "out of memory\n");
      return 0;
  }

  memcpy(buff, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
  memcpy(buff + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
            sizeof(struct in_addr));

  /* Tests whether cookie matches one of our secrets */
  if(ck_secrets_exist((unsigned char *)buff, length,
        const_cast<unsigned char *>(cookie), cookie_len) == 1 )  {
        OPENSSL_free(buff);
        return 1;
    }
    OPENSSL_free(buff);
    return 0;
}
