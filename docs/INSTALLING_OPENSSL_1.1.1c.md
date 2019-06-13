# 1 March 2019: New Long Term Support version of OpenSSL - 1.1.1c with SCTP support

~~~bash
curl https://www.openssl.org/source/openssl-1.1.1c.tar.gz \
--output openssl-1.1.1c.tar.gz && \
 tar -zxvf openssl-1.1.1c.tar.gz && \
 cd openssl-1.1.1c && \
 CFLAGS=-fPIC ./config shared zlib-dynamic sctp \
 --prefix=/opt/openssl/1.1.1c --openssldir=/usr/local/ssl/openssl/1.1.1c \
 --debug -Wl,--enable-new-dtags,-rpath,'\$(LIBRPATH)' && \
 make -j$(nproc) && make test && sudo make install
~~~

I had failing tests when compiling with the sctp option (needed for the SCTP programs)

~~~
../test/recipes/80-test_ssl_new.t .................. Dubious, test returned 6 (wstat 1536, 0x600)
Failed 6/29 subtests 
~~~

This problem disappears when I compile with the following options:
~~~
CFLAGS=-fPIC ./config shared zlib-dynamic \
 --prefix=/opt/openssl/1.1.1c --openssldir=/usr/local/ssl/openssl/1.1.1c \
 --debug -Wl,--enable-new-dtags,-rpath,'\$(LIBRPATH)'
~~~

I just went ahead and ran sudo make install with the sctp version that failed tests

# Create symbolic links in the /bin folder to the new versions.
-   `dpkg -L openssl` to determine where the system installation of OpenSSL is.
-   In my case it was `/usr/bin`.
-   Navigate to this folder using the terminal.

~~~bash
sudo ln -s /opt/openssl/1.1.1c/bin/openssl /usr/bin/openssl-1.1.1c
sudo ln -s /opt/openssl/1.1.1c/bin/c_rehash /usr/bin/c_rehash-1.1.1c
~~~

-   Now, when you run `openssl-1.1.1c` in a terminal, this new installation will be used.

# Uninstalling
~~~
export OSSL_V=1.1.1c
sudo rm -rf /opt/openssl/${OSSL_V} && \
sudo rm -rf /usr/local/ssl/openssl/${OSSL_V} && \
sudo rm /usr/bin/openssl-${OSSL_V} && \
sudo rm /usr/bin/c_rehash-${OSSL_V}
~~~


