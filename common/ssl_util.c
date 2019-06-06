/**
 * ssl_util.c
 */

#include "ssl_util.h"
#include <unistd.h>
#include <stdbool.h>

static int init_ssl_ctx(SSL_CTX **, bool server);

int init_client_ssl_ctx(SSL_CTX **ctx_ptr)
{ return init_ssl_ctx(ctx_ptr, false); }

int init_server_ssl_ctx(SSL_CTX **ctx_ptr)
{ return init_ssl_ctx(ctx_ptr, true); }

int close_ssl_ctx(SSL_CTX *ctx)
{
  ERR_free_strings();
  SSL_CTX_free(ctx);
  return 0;
}

int load_certificates(SSL_CTX *ctx,
    const char * const cert,
    const char * const key)
{
  int ret = 0;
  if (access(cert, F_OK) != 0) {
    fprintf(stderr, "%s:%d Certificate file %s not found\n", __FILE__, __LINE__, cert);
    ret = -1;
  }
  else if (access(key, F_OK) != 0) {
    fprintf(stderr, "%s:%d Key file %s not found\n", __FILE__, __LINE__, key);
    ret = -1;
  }
  // set cert
  else if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
    ssl_perror("Failed to set certificate file");
    ret = -1;
  }
  // set private key
  else if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
    ssl_perror("Failed to set key file");
    ret = -1;
  }
  else if (!SSL_CTX_check_private_key(ctx)) {
    ssl_perror("Failed to validate private key");
    ret = -1;
  }

  return ret;

}

void show_certificates(FILE *stream, SSL *ssl)
{
  X509 *cert = SSL_get_peer_certificate(ssl);

  if (cert == NULL) {
    fprintf(stderr, "No certificates\n");
    return;
  }

  fprintf(stderr, "Server certificates:\n");
  char *line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
  fprintf(stderr, "Subject: %s\n", line);
  free(line);

  line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
  fprintf(stderr, "Issuer: %s\n", line);
  free(line);
  X509_free(cert);
}

static int init_ssl_ctx(SSL_CTX **ctx_ptr, bool server)
{
  SSL_library_init();

  // add error strings
  SSL_load_error_strings();
  ERR_load_crypto_strings();

  (*ctx_ptr) = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());

  if ((*ctx_ptr) == NULL) {
    ssl_perror("Failed to create CTX\n");
    return -1;
  }

  int mode = server ?  SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE : SSL_VERIFY_NONE;
  SSL_CTX_set_verify((*ctx_ptr), mode, NULL);

  // disable SSLv23
  SSL_CTX_set_options(*ctx_ptr, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  return 0;
}
