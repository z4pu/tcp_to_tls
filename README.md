# Introduction


## Installation requirements

On Ubuntu, use the following command line to install cmake
~~~bash
sudo apt-get install -y \
    cmake  # to build program. At least version 3.7 needed
~~~

-   Install OpenSSL v 1.1.1b using instructions in `docs/INSTALLING_OPENSSL_1.1.1b.md`

## Building the Executables

Pre-requisites: CMAKE 3.7

~~~bash
# Generate makefiles for debug build
cmake -H. -B_builds -DCMAKE_BUILD_TYPE=Debug

# Generate makefiles for debug build with address sanitization
# Good if your programs produce a segmentation fault while running
cmake -H. -B_builds -DCMAKE_BUILD_TYPE=Debug -DBUILD_ASAN=ON

# Debug with verbose output; good for debugging builds
cmake -H. -B_builds -DCMAKE_BUILD_TYPE=Debug \
-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON

#3  Possible values for -DCMAKE_BUILD_TYPE are
# Debug, Release, RelWithDebInfo and MinSizeRel
cmake -H. -B_builds -DCMAKE_BUILD_TYPE=Release
cmake -H. -B_builds -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake -H. -B_builds -DCMAKE_BUILD_TYPE=MinSizeRel

# Build
cd _builds
make
~~~

## Running the executables

Running `make` builds 4 executables in the `bin` folder:

| Executable name | Description |
|---|---|
| server_tcp  | Waits for a client to connect and send a string. Reverses it and sends it back to the client. |
| client_tcp  | Connects to server and sends it a string. Waits for the server to respond. then disconnects.  |
| server_tls  | As with server_tcp, but over a TLS connection  |
| client_tls  | As with client_tcp, but over a TLS connection  |


**server_tcp and client_tcp**

~~~bash
./server_tcp -p <port to listen>
./client_tcp -h <server IP> -p <server listening port> \
    -s <string to reverse>

# EXAMPLE
./server_tcp -p 4000
./client_tcp -h 127.0.0.1 -p 4000 -s dhw873g17GBFb2712
~~~

**server_tls and client_tls**

~~~bash
# Generate the certificates for the TLS connection
cd certs
# Example:
# X.509v1 certificates
./generate_certificate_and_key.sh \
-s "/O=Test/OU=Server/CN=127.0.0.1" \
-c "/O=Test/OU=Client/CN=127.0.0.1"
# The CN (Common Name) must match the IP addresses of your containers or hosts
# Security note: The output private keys are NOT encrypted
# If you wish to encrypt the private keys, your application must set
# SSL_CTX_set_default_passwd_cb or SSL_set_default_passwd_cb
# Or, for X.509v3 certificates
# Make changes to the config files in openssl_conf_files if required
# https://www.openssl.org/docs/man1.1.1/man5/x509v3_config.html
# https://access.redhat.com/documentation/en-US/Red_Hat_Certificate_System/8.0/html/Admin_Guide/Standard_X.509_v3_Certificate_Extensions.html
./generate_certificate_and_key_x509v3.sh

# Install the certauth.crt for centos or debian
./install_ca_cert.sh -o debian

# Run the executables
./server_tls -p <port to listen>
./client_tls -h <server IP> -p <server's listening port> \
    -s <string to reverse>

# EXAMPLE
./server_tls -p 4000
./client_tls -h 127.0.0.1 -p 4000 -s dhw873g17GBFb2712
~~~
