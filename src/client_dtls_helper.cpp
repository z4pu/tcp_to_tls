#include "client_tls_helper.hpp"
#include "common_tls.hpp"
#include "common.hpp"

#include <iostream>



SSL_CTX* DTLSInitClientContextFromKeystore(SSL_CTX* ctx, const char* cert_file,
    const char* privkey_file, const char* trusted_certs_file)
{
    int result = 0;

// OLD OPENSSL_VERSION_NUMBER  0x1000114fL
// 1.02 OPENSSL_VERSION_NUMBER  0x100020bfL
// Create a new context using TLS

if (!FileExists(privkey_file))  {
    std:: cerr << "DTLSInitClientContextFromKeystore(): !FileExists(privkey_file)" << std::endl;
    return nullptr;
}
if (!FileExists(cert_file))  {
    std:: cerr << "DTLSInitClientContextFromKeystore(): !FileExists(cert_file)" << std::endl;
    return nullptr;
}
if (!FileExists(trusted_certs_file))  {
    std:: cerr << "DTLSInitClientContextFromKeystore(): !FileExists(trusted_certs_file)" << std::endl;
    return nullptr;
}
    ctx = SSL_CTX_new(DTLS_client_method());
    if (ctx == NULL) {
        OSSLErrorHandler("Cannot create SSL Context");
        return nullptr;
    }

    result = SSL_CTX_set_min_proto_version(ctx, DTLS1_2_VERSION);
    if (result == 0) {
        OSSLErrorHandler("DTLSInitClientContextFromKeystore(): SSL_CTX_set_min_proto_version()");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    result = SSL_CTX_set_cipher_list(ctx, FULLCIPHERLIST);
    if (result != 1)     {
        OSSLErrorHandler("DTLSInitClientContextFromKeystore(): Error setting cipher list");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    SSL_CTX_set_default_passwd_cb(ctx, NULL);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    result = SSL_CTX_use_certificate_file(ctx, cert_file,
        SSL_FILETYPE_PEM);
    if (result != 1)        {
        OSSLErrorHandler("DTLSInitClientContextFromKeystore(): Can't read certificate file\n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Load private key
    result = SSL_CTX_use_PrivateKey_file(ctx, privkey_file, SSL_FILETYPE_PEM);
    if (result != 1)     {
        OSSLErrorHandler("DTLSInitClientContextFromKeystore(): Can't read key file\n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Check if the private key is valid
    result = SSL_CTX_check_private_key(ctx);
    if (result != 1)        {
        OSSLErrorHandler("DTLSInitClientContextFromKeystore(): checking the private key failed. \n");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if(!(SSL_CTX_load_verify_locations(ctx, trusted_certs_file, nullptr)))        {
        OSSLErrorHandler("DTLSInitClientContextFromKeystore(): Can't load_verify_locations");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    ctx = LoadECParamsInContext(ctx);

    return ctx;
}

int SetPeerAsDTLSEndpoint(const int &peer_fd, const sockaddr_in &peer_addr, SSL * const ssl)
{
    BIO * dgramBio = nullptr;

    dgramBio = BIO_new_dgram(peer_fd, BIO_NOCLOSE);
    if (!dgramBio) {
        OSSLErrorHandler("SetPeerAsDTLSEndpoint(): BIO_new_dgram(): cannot set peer fd");
        return -1;
    }

    if (BIO_ctrl_dgram_connect(dgramBio, &peer_addr) == 0) {
        BIO_free(dgramBio);
        return -1;
    }

    SSL_set_bio(ssl, dgramBio, dgramBio);

    return 0;
}
