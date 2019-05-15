# 1 March 2019: New Long Term Support version of OpenSSL - 1.1.1b

~~~bash
curl https://www.openssl.org/source/openssl-1.1.1b.tar.gz \
--output openssl-1.1.1b.tar.gz && \
 tar -zxvf openssl-1.1.1b.tar.gz && \
 cd openssl-1.1.1b && \
 CFLAGS=-fPIC ./config shared zlib-dynamic \
 --prefix=/opt/openssl/1.1.1b --openssldir=/usr/local/ssl/openssl/1.1.1b \
 --debug -Wl,--enable-new-dtags,-rpath,'\$(LIBRPATH)' && \
 make -j$(nproc) && make test && sudo make install
~~~

# Create symbolic links in the /bin folder to the new versions.
-   `dpkg -L openssl` to determine where the system installation of OpenSSL is.
-   In my case it was `/usr/bin`.
-   Navigate to this folder using the terminal.

~~~bash
sudo ln -s /opt/openssl/1.1.1b/bin/openssl /usr/bin/openssl-1.1.1b
sudo ln -s /opt/openssl/1.1.1b/bin/c_rehash /usr/bin/c_rehash-1.1.1b
~~~

-   Now, when you run `openssl-1.1.1b` in a terminal, this new installation will be used.

# Uninstalling
~~~
export OSSL_V=1.1.1b
sudo rm -rf /opt/openssl/${OSSL_V} && \
sudo rm -rf /usr/local/ssl/openssl/${OSSL_V} && \
sudo rm /usr/bin/openssl-${OSSL_V} && \
sudo rm /usr/bin/c_rehash-${OSSL_V}
~~~
