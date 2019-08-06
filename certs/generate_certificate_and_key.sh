#!/usr/bin/env bash
# This script generates X.509v1 certificates using the prime256v1 curve for
# the TLS connection between the server and client
#
#
# Usage:
#     ./generate_certificate_and_key.sh [options]
# Options:
#     -s <server subject>    # Subject string for server
# (interactive if null)
#     -c <client subject>    # Subject string for client (interactive if null)
# Example: (The double spaces for empty fields are needed)
#  ./generate_certificate_and_key.sh -s "/O=Test/OU=Server/CN=127.0.0.1" -c "/O=Test/OU=Client/CN=127.0.0.1"
# The CN (Common Name) must match the IP addresses of your containers or hosts

if [ $# -eq 0 ]; then
    echo "No command specified" >&2
    exit 1
fi

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

while getopts ":s:c:" opt; do
  case $opt in
    s)
      SERVERSUBJ=$OPTARG
      ;;
    c)
      CLIENTSUBJ=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done


# Generate certauth.crt and certauth.key for self-signed certificate
# authority if certauth.key and certauth.crt don't already exist
echo "Generating self-signed X509 Certificate to issue TLS certificates to server and client"
if [ ! -e certauth.key ] || [ ! -e certauth.crt ]; then
  $OSSL ecparam -genkey -name prime256v1 -out certauth.key
  $OSSL req -new -sha256 -key certauth.key -out certauth.csr \
  -subj "/O=Test/OU=Self-Signed CA/CN=CA"
  $OSSL req -x509 -sha256 -days 3650 -key certauth.key -in certauth.csr \
  -out certauth.crt
fi

# Server
# PEM Private key
$OSSL ecparam -name prime256v1 -genkey -noout -out server.key
# CSR
echo
echo "Generating certificate signing request for Server"
if [ -z "$SERVERSUBJ" ]; then
  $OSSL req -new -sha256 -key server.key -out server.csr
else
  $OSSL req -new -sha256 -key server.key -out server.csr \
  -subj "$SERVERSUBJ"
fi
# DER public key for server
$OSSL pkey -inform PEM -outform der -in server.key -pubout \
-out serverpubder.key

#sign csr to get server.crt
$OSSL x509 -req -days 2555 -in server.csr -CA certauth.crt \
-CAkey certauth.key -CAcreateserial -out serverjust.crt

# Generate PEM Public Key for server
$OSSL ec -in server.key -pubout -out serverpub.key

# append certificate to private key for server
cat server.key serverjust.crt > server.crt

# For Client
# PEM private key
$OSSL ecparam -name prime256v1 -genkey -noout -out client.key

#CSR
echo
echo "Generating certificate signing request for client"
if [ -z "$CLIENTSUBJ" ]; then
  $OSSL req -new -sha256 -key client.key -out client.csr
else
  $OSSL req -new -sha256 -key client.key -out client.csr \
  -subj "$CLIENTSUBJ"
fi
#sign csr to get cert
$OSSL x509 -req -days 2555 -in client.csr -CA certauth.crt \
-CAkey certauth.key -CAcreateserial -out clientjust.crt

# PEM public key
$OSSL ec -in client.key -pubout -out clientpub.key

# append certificate to private key for client
cat client.key clientjust.crt > client.crt

