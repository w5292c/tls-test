#include <stdio.h>
#include <wolfssl/ssl.h>
#include <wolfssl/openssl/pem.h>

int main(int argc, char **argv)
{
  fprintf(stdout, "Starting server...\n");
  if (argc < 2) {
    fprintf(stderr, "Error: no *.pem file specified\n");
    return 1;
  }
  const char *const pemFilename = argv[1];
  fprintf(stdout, "Using PEM file: \"%s\"\n", pemFilename);
  FILE *const pemFile = fopen(pemFilename, "r");
  if (!pemFile) {
    fprintf(stderr, "Error: cannot open PEM file: \"%s\"\n", pemFilename);
    return 1;
  }
  WOLFSSL_RSA *const pubKey = PEM_read_RSAPublicKey(pemFile, NULL, NULL, NULL);
  fclose(pemFile);
  if (!pubKey) {
    fprintf(stderr, "Error: failed reading PEM file\n");
    return 1;
  }

  char *const cipherList = wolfSSL_get_cipher_list(1);
  fprintf(stdout, "Here is the list: \"%s\"\n", cipherList);

  fprintf(stdout, "Done.\n");
  return 0;
}
