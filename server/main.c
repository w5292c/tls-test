#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

int main(int argc, char **argv)
{
  mbedtls_rsa_context rsaContext;
  mbedtls_rsa_init(&rsaContext, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_SHA256);

  fprintf(stdout, "Starting server...\n");
  if (argc < 2) {
    fprintf(stderr, "Error: no public/private key files specified\n");
    return 1;
  }

  /* Loading the RSA private key file */
  const char *const privateFilename = argv[1];
  fprintf(stdout, "Info: private key file: \"%s\"\n", privateFilename);

  FILE *privateFile = fopen(privateFilename, "rb");
  if (!privateFile) {
    fprintf(stderr, "Error: failed openning the private key file: \"%s\"\n", privateFilename);
    goto finish;
  }

  int result = mbedtls_mpi_read_file(&rsaContext.N , 16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'N' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.E,  16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'E' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.D,  16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'D' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.P,  16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'P' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.Q,  16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'Q' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.DP, 16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'DP' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.DQ, 16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'DQ' for the RSA key\n");
    goto finish;
  }
  result = mbedtls_mpi_read_file(&rsaContext.QP, 16, privateFile);
  if (result) {
    fprintf(stderr, "Error: failed reading 'QP' for the RSA key\n");
    goto finish;
  }
  rsaContext.len = (mbedtls_mpi_bitlen(&rsaContext.N) + 7 ) >> 3;
  fclose(privateFile);
  privateFile = NULL;

  /* Checking keys */
  result = mbedtls_rsa_check_pubkey(&rsaContext);
  if (result) {
    fprintf(stderr, "Error: failed checking public key in the RSA context, code: %d\n", result);
    goto finish;
  }
  result = mbedtls_rsa_check_privkey(&rsaContext);
  if (result) {
    fprintf(stderr, "Error: failed checking private key in the RSA context, code: %d\n", result);
    goto finish;
  }

  mbedtls_entropy_context entropyContext;
  mbedtls_entropy_init(&entropyContext);

  mbedtls_ctr_drbg_context drbgContext;
  mbedtls_ctr_drbg_init(&drbgContext);
  result = mbedtls_ctr_drbg_seed(&drbgContext, mbedtls_entropy_func, &entropyContext, NULL, 0);
  if (result) {
    fprintf(stderr, "Error: failed seeding the DRBG, code: %d\n", result);
    goto finish;
  }

  /* Allocate a buffer for RSA-encoded data */
  unsigned char *const output = calloc(1, rsaContext.len);
  if (!output) {
    fprintf(stderr, "Error: failed allocating %lu bytes for the output buffer\n",
                    (unsigned long)rsaContext.len);
    goto finish;
  }

  /* Encode a test string in RSA/private mode */
  const char *const inputString = "Hello, this is a test string";
  const size_t inputStringLength = strlen(inputString);
  result = mbedtls_rsa_pkcs1_encrypt(&rsaContext,
                                     mbedtls_ctr_drbg_random,
                                     &drbgContext,
                                     MBEDTLS_RSA_PRIVATE, inputStringLength,
                                     (const unsigned char *)inputString,
                                     output);
  if (result) {
    fprintf(stderr, "Error: encryption failed, code: %d\n", result);
    goto finish;
  }
  /* Print the encoded data */
  int i;
  for (i = 0; i < rsaContext.len; ++i) {
    if (!(i % 16)) {
      fprintf(stdout, "%8.8d ", i);
    }
    fprintf(stdout, "%2.2x", output[i]);
    if (3 == (i % 4)) {
      fprintf(stdout, " ");
    }
    if (15 == (i % 16)) {
      fprintf(stdout, "\n");
    }
  }

  /* Decode the encoded data */
  char *const restored = calloc(1, 1024);
  if (!restored) {
    fprintf(stderr, "Error: failed allocating the buffer for the restored data\n");
    goto finish;
  }
  size_t olen = 0;
  result = mbedtls_rsa_pkcs1_decrypt(&rsaContext, NULL, NULL,
                                     MBEDTLS_RSA_PUBLIC, &olen,
                                     output,
                                     restored, 1024);
  fprintf(stdout, "Restored data length: %lu vs original length: %lu\nRestored data: \"%s\"\n",
                  (unsigned long)olen, (unsigned long)inputStringLength, restored);
  if (olen != inputStringLength || strncmp(restored, inputString, inputStringLength)) {
    fprintf(stderr, "Error: decoded to a wrong data: \"%s\" vs \"%s\"\n", restored, inputString);
    goto finish;
  }

finish:
  free(restored);
  free(output);
  mbedtls_ctr_drbg_free(&drbgContext);
  mbedtls_entropy_free(&entropyContext);
  if (privateFile) {
    fclose(privateFile);
    privateFile = NULL;
  }
  mbedtls_rsa_free(&rsaContext);
  fprintf(stdout, "Done.\n");
  return 0;
}
