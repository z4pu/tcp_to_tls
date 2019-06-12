#include "server_tls_helper.hpp"
#include "server_tcp_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

#include <iostream>

extern "C" {
    #include "ck_secrets_vault.h"
}

extern "C" {
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <netinet/in.h>
    #include <sys/un.h>
    #include <arpa/inet.h>
}

/**
* @brief Initialise and populate global SSL_CTX* for TLS connection
* @param [in] nothing
* @return -1 if error, 0 if successful
*/

SSL_CTX* TLSInitServerContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* trusted_certs_file)
{
    int result = 0;


    // OLD OPENSSL_VERSION_NUMBER  0x1000114fL
    // 1.02 OPENSSL_VERSION_NUMBER  0x100020bfL
    // Create a new context using TLS

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
         OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_new(SSLv23_server_method()): Cannot create SSL Context");
         return nullptr;
    }

    result = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (result == 0) {
        OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_set_min_proto_version()");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    // Set our supported ciphers
    result = SSL_CTX_set_cipher_list(ctx, FULLCIPHERLIST);
    if (result != 1)    {
      OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_set_cipher_list()");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    SSL_CTX_set_default_passwd_cb(ctx, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    // Load the certificate file; contains also the public key
    if (!FileExists(cert_file))  {
        std:: cerr << "TLSInitServerContextFromKeystore(): !FileExists(SERVER_CERTIFICATE)" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    result = SSL_CTX_use_certificate_file(ctx, cert_file,
            SSL_FILETYPE_PEM);
    if (result != 1)      {
      OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_use_certificate_file()");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    // Load private key
    if (!FileExists(privkey_file))  {
        std:: cerr << "TLSInitServerContextFromKeystore(): !FileExists(SERVER_PRIVATEKEY)" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    result = SSL_CTX_use_PrivateKey_file(ctx, privkey_file, SSL_FILETYPE_PEM);
    if (result != 1)      {
      OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_use_PrivateKey_file()");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(ctx);
    if (result != 1)        {
      OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_check_private_key(ctx)");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    if (!FileExists(trusted_certs_file))  {
        std:: cerr << "TLSInitServerContextFromKeystore(): !FileExists(trusted_certs_file)" << std::endl;
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if(!(SSL_CTX_load_verify_locations(ctx, trusted_certs_file, nullptr)))      {
      OSSLErrorHandler("TLSInitServerContextFromKeystore(): SSL_CTX_load_verify_locations(ctx)");
      SSL_CTX_free(ctx);
      return nullptr;
    }

    ctx = LoadECParamsInContext(ctx);

    return ctx;
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

    result = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
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

void ProcessTLSClient (SSL * const ssl){
    int r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    std::string instring, outstring;

    r = ReceiveMessageTLS(ssl, buff);
    if (r == -1) {
        perror("ProcessTLSClient(): ReceiveMessageTLS()");
        return;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendStringSize(reversed string)");
        return;
    }

    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendString(reversed string)");
        return;
    }

    #ifdef DEBUG
        std::cout <<  "--> ProcessTLSClient(): OK, reversed string: "
        << buff << std::endl;
    #endif

    return;
}

void ProcessDTLSClient (const int &server_fd, SSL_CTX * const ctx){
    int r, cookie_r = 0;
    unsigned char buff[MAX_STRING_LENGTH+1] = {};
    std::string instring, outstring;
    BIO * dgramBio = nullptr;
    SSL * ssl = nullptr;
    BIO_ADDR* client_addr_bio = nullptr;

    dgramBio = BIO_new_dgram(server_fd, BIO_NOCLOSE);
    if (!dgramBio) {
        OSSLErrorHandler("ProcessDTLSClient(): BIO_new_dgram(): cannot create from fd");
        return;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL){
        OSSLErrorHandler("ProcessDTLSClient(): SSL_new(): ");
        return;
    }

    // Now SSL will apply to all data coming from the file descriptor
    SSL_set_bio(ssl, dgramBio, dgramBio);
    SSL_set_accept_state(ssl);

    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);



    printf("DTLS Listening ...\n");
    do {
        cookie_r = DTLSv1_listen(ssl, client_addr_bio);
    }    while (cookie_r < 1);
    if (cookie_r < 0) {
        OSSLErrorHandler("ProcessDTLSClient(): DTLSv1_listen(): ");
        return;
    }

    std::cout << "Cookie exchange OK\n";

    r = ReceiveMessageTLS(ssl, buff);
    if (r == -1) {
        perror("ProcessTLSClient(): ReceiveMessageTLS()");
        return;
    }

    ReverseString(reinterpret_cast<char*>(buff));

    r = SendStringSizeTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendStringSize(reversed string)");
        return;
    }

    r = SendStringTLS(ssl, reinterpret_cast<char*>(buff));
    if (r == -1) {
        perror("ProcessTLSClient(): SendString(reversed string)");
        return;
    }

    #ifdef DEBUG
        std::cout <<  "--> ProcessTLSClient(): OK, reversed string: "
        << buff << std::endl;
    #endif

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

  if (buff == NULL)
  {
      BIO_printf(bio_err, "out of memory\n");
      return 0;
  }

  memcpy(buff, &peer.s4.sin_port, sizeof(peer.s4.sin_port));
  memcpy(buff + sizeof(peer.s4.sin_port), &peer.s4.sin_addr,
                            sizeof(struct in_addr));

  /* Tests whether cookie matches one of our secrets */
  if(ck_secrets_exist((unsigned char *)buff, length,
                      const_cast<unsigned char *>(cookie), cookie_len) == 1 )
    {return 1;}

    return 0;
}
