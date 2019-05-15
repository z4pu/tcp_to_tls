#include "client_tls_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

#include <iostream>

SSL_CTX* TlsInitClientContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* trusted_certs_file)
{
    int result = 0;

// OLD OPENSSL_VERSION_NUMBER  0x1000114fL
// 1.02 OPENSSL_VERSION_NUMBER  0x100020bfL
// Create a new context using TLS

if (!FileExists(privkey_file))  {
    std:: cerr << "TlsInitClientContextFromKeystore(): !FileExists(privkey_file)" << std::endl;
    return nullptr;
}
if (!FileExists(cert_file))  {
    std:: cerr << "TlsInitClientContextFromKeystore(): !FileExists(cert_file)" << std::endl;
    return nullptr;
}
if (!FileExists(trusted_certs_file))  {
    std:: cerr << "TlsInitClientContextFromKeystore(): !FileExists(trusted_certs_file)" << std::endl;
    return nullptr;
}
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        OSSLErrorHandler("Cannot create SSL Context");
        return nullptr;
    }

    result = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if (result == 0) {
        OSSLErrorHandler("TlsInitClientContextFromKeystore(): SSL_CTX_set_min_proto_version()");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    result = SSL_CTX_set_cipher_list(ctx, FULLCIPHERLIST);
    if (result != 1)     {
        OSSLErrorHandler("Error setting cipher list");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    SSL_CTX_set_default_passwd_cb(ctx, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    result = SSL_CTX_use_certificate_file(ctx, cert_file,
        SSL_FILETYPE_PEM);
    if (result != 1)        {
        OSSLErrorHandler("Can't read certificate file\n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(ctx, privkey_file, SSL_FILETYPE_PEM);
    if (result != 1)     {
        OSSLErrorHandler("Can't read key file\n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(ctx);
    if (result != 1)        {
        OSSLErrorHandler("Error: checking the private key failed. \n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if(!(SSL_CTX_load_verify_locations(ctx, trusted_certs_file, nullptr)))        {
        OSSLErrorHandler("Can't load_verify_locations");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    ctx = LoadECParamsInContext(ctx);

    return ctx;
}

int SendRequestTLS(SSL* const ssl, const char * string)
{
    int r, string_length = 0;
    string_length = SendStringSizeTLS(ssl, string);
    if (string_length == -1) {
        perror("SendRequestTLS(): SendStringSizeTLS()");
        return -1;
    }
    r = SendStringTLS(ssl, string);
    if (r == -1){
        perror("SendRequestTLS(): SendStringTLS()");
        return -1;
    }
    #ifdef DEBUG
        std::cout << "--> SendRequestTLS(): " << string << std::endl;
    #endif
    return 0;
}
