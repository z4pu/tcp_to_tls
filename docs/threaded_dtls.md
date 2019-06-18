# Issue:

<https://mta.openssl.org/pipermail/openssl-users/2018-August/008533.html>


To support multiple clients I tried two approaches:
1. singled threaded async IO, preferred since I have to deal with many clients
2. multi threaded, one thread per client

Both approaches seem to be doomed for the very same reason, namely that
DTLSv1_listen() does peek into the kernel queue and does not consume
the client hello from the UDP socket.

Both loop around DTLSv1_listen() and as soon the function returns > 0 a new
socket for the client is created using bind/connect and the client address
as returned by DTLSv1_listen().

This client socket is then passed to a new thread or feed into the event loop.
In both cases the client hello is still in the queue of the server socket
and the program will over and over create new client sockets.

After searching the web for examples I've found this thread[0], where the approaches
I tried are advertised.
In [1] the demo server at [3] is suggested as good example.

dtls_udp_echo.c from [3] does exactly what I did in my 2nd approach, and it fails in
the same way.
As soon one client connects, it creates over and over new sockets until it dies due
to too many open files.

After digging a bit into the source it looks to me like since commit [3],
DTLSv1_listen() assumes that you re-use the same socket for the new client.
Which makes supporting multiple clients impossible.

Given that I'm not an OpenSSL DTLS expert I still hope I miss something.
Can you please help me to figure what the correct approach for multiple clients is?

Links:
<https://mta.openssl.org/pipermail/openssl-users/2017-November/006987.html>
<https://mta.openssl.org/pipermail/openssl-users/2018-August/008534.html>
Have a look at:

http://www.wangafu.net/~nickm/libevent-book/Ref6a_advanced_bufferevents.html

you don’t need a dedicated thread per connection.

See the section “Bufferevents and SSL”

You can create an SSL context and then bind a connection listener to it.

If the library doesn’t specifically handle the case of DTLS (I know it handles SSL and TLS), then it shouldn’t be too hard to cobble something together and even get it upstreamed.

# Repo:

https://github.com/nplab/DTLS-Examples
