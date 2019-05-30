# openssl_nonblocking_connection

This repository (fork from [darenjs/openssl_examples](https://github.com/darenjs/openssl_examples)) serves as an example of how to use OpenSSL's C API, paired with non-blockign socket programming to establish a secure connection between two nodes.
OpenSSL's C API is horrific. It is a pain to try to write something just looking at the documentation. After long weeks trying to find an example, I found [darenjs](https://github.com/darenjs)'s repo, which was a breeze of fresh air. However, I found two problems: 1) the use of `poll` includes an efficiency problem; 2) the code is tightly coupled (to say the least). The effort here was twofold: to use `select` and to provide an abstraction on OpenSSL that allows for reuse of the code.

The design is laid out on the wiki.

<!--
## examples of using OpenSSL

`ssl_server_nonblock.c` is a simple OpenSSL example program to illustrate the use
of memory BIO's (BIO_s_mem) to perform SSL read and write with non-blocking
socket IO.

The program accepts connections from SSL clients.  To keep it simple only a
single live connection is supported.  While a client is connected the program
will receive any bytes which it sends, unencrypt them and write to stdout, using
non-blocking socket reads.  It will also read from stdin, encrypt the bytes and
send to the client, using non-blocking socket writes.

Note that this program is single threaded. This means it does not have to set up
SSL locking.  The program does not exit, and so it does not have code to free up
the resources associated with the SSL context and library.

`ssl_client_nonblock.c` is a client version of the same program.
-->

Prerequisites
-----------

apt based distro's (Ubuntu, Debian)
```bash
$ sudo apt install openssl libssl-dev
```

yum/dnf based distro's (Fedora, CentOS, RHEL)
```bash
$ sudo dnf install openssl openssl-devel
```

How to compile
-----------

```bash
$ make
```
Simple, no?

How to generate certificates
-----------

A Makefile target exists to do this, if you want to see how it was done, look inside!
```bash
$ make certs
```

Running
-------

To run server:
```bash
$ ./server [port = 55555]
```

To run client:
```bash
$ ./client [ip = 127.0.0.1] [port = 55555]
```

`openssl` has a default client program, that can be used to test the server
```bash
$ ./server 55555
$ openssl s_client -connect 127.0.0.1:55555 -msg -debug -state -showcerts
```

Configuration
-------
Some values are hardcoded (to make running less painful).
Check `common/config.h` for those values (and change them if you will).

Future Directions
-------
None.
I have another repo, [secure-chat](https://github.com/BSDinis/secure-chat) that uses this interface to implement a toy chat service with TLS.
Maybe, one day, if I have the time, I'll make this library better.

If you have any question/want something, don't hesitate to open an issue.
