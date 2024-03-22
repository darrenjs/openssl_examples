# openssl_examples

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

Compilation
-----------

To compile the program, use something like:

```console
    gcc ssl_server_nonblock.c -Wall -O0 -g3 -std=c99 -lcrypto -lssl -o ssl_server_nonblock
```

Or on MacOS:

```console
 gcc -Wall -O0 -g3 -std=c99 -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib -lssl -lcrypto  -o ssl_server_nonblock ssl_server_nonblock.c
 ```

if you get link errors from ld for SSL
```console
    gcc ssl_server_nonblock.c -Wall -O0 -g3 -std=c99 -o ssl_server_nonblock -lcrypto -lssl

Or just try the makefile, for Linux platforms.

On Ubuntu systems you may need to run `sudo apt install libssl-dev` to install OpenSSL headers.

Running
-------

Running the program requires that a SSL certificate and private key are
available to be loaded. These can be generated using the 'openssl' program using
these steps:

1. Generate the private key, this is what we normally keep secret:
```console
    openssl genrsa -des3 -passout pass:ABCD -out server.pass.key 2048
    openssl rsa -passin pass:ABCD -in server.pass.key -out server.key
    rm -f server.pass.key
```
2. Next generate the CSR.  We can leave the password empty when prompted
   (because this is self-sign):
```console
    openssl req -new -key server.key -out server.csr
```
3. Next generate the self signed certificate:
```console
    openssl x509 -req -sha256 -days 365 -in server.csr -signkey server.key -out server.crt
    rm -f server.csr
```
The openssl program can also be used to connect to this program as an SSL
client. Here's an example command (assuming we're using port 55555):
```console
    openssl s_client -connect 127.0.0.1:55555 -msg -debug -state -showcerts
```

Flow of encrypted & unencrypted bytes
-------------------------------------

This diagram shows how the read and write memory BIO's (rbio & wbio) are
associated with the socket read and write respectively.  On the inbound flow
(data into the program) bytes are read from the socket and copied into the rbio
via BIO_write.  This represents the the transfer of encrypted data into the SSL
object. The unencrypted data is then obtained through calling SSL_read.  The
reverse happens on the outbound flow to convey unencrypted user data into a
socket write of encrypted data.

```
  +------+                                    +-----+
  |......|--> read(fd) --> BIO_write(rbio) -->|.....|--> SSL_read(ssl)  --> IN
  |......|                                    |.....|
  |.sock.|                                    |.SSL.|
  |......|                                    |.....|
  |......|<-- write(fd) <-- BIO_read(wbio) <--|.....|<-- SSL_write(ssl) <-- OUT
  +------+                                    +-----+

          |                                  |       |                     |
          |<-------------------------------->|       |<------------------->|
          |         encrypted bytes          |       |  unencrypted bytes  |
```
