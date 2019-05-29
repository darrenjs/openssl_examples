// implemtation

#include "macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>

void error_kill(const char *file, int lineno, const char *msg)
{
  error_log(file, lineno, msg);
  exit(EXIT_FAILURE);
}

void error_log(const char *file, int lineno, const char *msg)
{
  fprintf(stderr, "%s:%d %s\n", file, lineno, msg);
  ERR_print_errors_fp(stderr);
}

void die(const char *msg)
{
  // FIXME
  perror(msg);
  exit(1);
}
