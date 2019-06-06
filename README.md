# openssl_nonblocking_connection

This repository (fork from [darenjs/openssl_examples](https://github.com/darenjs/openssl_examples)) serves as an example of how to use OpenSSL's C API, paired with non-blockign socket programming to establish a secure connection between two nodes.

OpenSSL's C API is horrific. It is a pain to try to write something just looking at the documentation. After long weeks trying to find an example, I found [darenjs](https://github.com/darenjs)'s repo, which was a breeze of fresh air. However, I found two problems: 1) the use of `poll` introduces an efficiency problem; 2) the code is tightly coupled (to say the least). 

The effort here was twofold: to use `select` and to provide an abstraction on OpenSSL that allows for reuse of the code.

The design is laid out on the wiki.


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
Right now, the server-side certificate verification is dummy. However, I ain't got the time to fix it now.

I have another repo, [secure-chat](https://github.com/BSDinis/secure-chat) that uses this interface to implement a toy chat service with TLS.
Maybe, one day, if I have the time, I'll make this library better.

If you have any question/want something, don't hesitate to open an issue.
