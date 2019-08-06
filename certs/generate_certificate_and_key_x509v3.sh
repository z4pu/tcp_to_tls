#!/usr/bin/env bash
# This script generates X.509v3 certificates using the prime256v1 curve for
# the TLS connection between the server and client
#
#
# Usage:
#     ./generate_certificate_and_key_x509v3.sh
#
# There are no command line options.
#       Edit the IP addresses in the files in openssl_conf_files
# See https://www.openssl.org/docs/man1.1.1/man5/x509v3_config.html



# Check openssl-1.1.1c is valid
if [[ $(which openssl-1.1.1c) ]]; then
    echo "openssl-1.1.1c found"
    OSSL="openssl-1.1.1c"
else
    if [ $(which openssl) ]; then
        echo "openssl found"
        OSSL="openssl"
    else
        echo "openssl not found"
        exit 1
    fi
fi


# Generate certauth.crt and certauth.key for self-signed certificate
# authority if certauth.key and certauth.crt don't already exist
echo "Generating self-signed X509 Certificate to issue TLS certificates to server and client"
if [ ! -e certauth.key ] || [ ! -e certauth.crt ]; then
  $OSSL ecparam -genkey -name prime256v1 -out certauth.key
  $OSSL req -new -sha256 -key certauth.key -out certauth.csr \
  -config ../openssl_conf_files/openssl.cnf -extensions v3_rootca \
  -subj "/O=Test/OU=Self-Signed CA/CN=CA"
  $OSSL req -x509 -sha256 -days 3650 \
    -config ../openssl_conf_files/openssl.cnf -extensions v3_rootca \
  -key certauth.key -in certauth.csr -out certauth.crt
fi
echo

# Server
echo "Generating certificate for Server"
$OSSL ecparam -name prime256v1 -genkey -noout -out server.key

$OSSL req -new -sha256 -key server.key -out server.csr \
  -config ../openssl_conf_files/openssl.cnf -extensions v3_end_tlsserver \
  -subj "/O=Test/OU=Server/CN=Server"
$OSSL x509 -req -days 2555 -in server.csr \
    -extfile ../openssl_conf_files/openssl.end_tls_server.cnf \
    -CA certauth.crt -CAkey certauth.key -CAcreateserial -out serverjust.crt
# append certificate to private key for server
cat server.key serverjust.crt > server.crt
# Generate PEM Public Key for server
$OSSL ec -in server.key -pubout -out serverpub.key
echo

# For Client
echo "Generating certificate for Client"
$OSSL ecparam -name prime256v1 -genkey -noout -out client.key

$OSSL req -new -sha256 -key client.key -out client.csr \
  -config ../openssl_conf_files/openssl.cnf -extensions v3_end_tlsclient \
  -subj "/O=Test/OU=Client/CN=Client"
#sign csr to get cert
$OSSL x509 -req -days 2555 -in client.csr \
    -extfile ../openssl_conf_files/openssl.end_tls_client.cnf \
    -CA certauth.crt -CAkey certauth.key -CAcreateserial -out clientjust.crt

# PEM public key
$OSSL ec -in client.key -pubout -out clientpub.key

# append certificate to private key for client
cat client.key clientjust.crt > client.crt

