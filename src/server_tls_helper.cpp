#include "server_tls_helper.hpp"
#include "server_tcp_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

#include <iostream>





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
