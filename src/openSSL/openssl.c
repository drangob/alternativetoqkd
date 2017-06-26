#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

void print_uint128(__uint128_t n)
{
    if (n == 0) {
      return;
    }

    print_uint128(n/10);
    putchar(n%10+0x30);
}

int encrypt(__uint128_t *ctr, unsigned char *key, unsigned char *output);

void handleErrors(void){}

int main (void) {

  FILE *fd = fopen("data.bin", "wb");

  /* Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  /* A 128 bit key */
  unsigned char *key = (unsigned char *)"0123456789012345";

  /* A 128 bit ctr */
  __uint128_t ctr = 0;

  /* Buffer for ciphertext. Ensure the buffer is long enough for the
   * ciphertext which may be longer than the plaintext, dependant on the
   * algorithm and mode
   */
  unsigned char output[16];

  int ciphertext_len;

  /* Initialise the library */
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  OPENSSL_config(NULL);

  for (int i = 0; i < 1; ++i) {
    ciphertext_len = encrypt (&ctr, key, output);
    ctr++;

    fwrite(output, ciphertext_len, 1, fd);
  }

  /* Clean up */
  EVP_cleanup();
  ERR_free_strings();

  return 0;
}


int encrypt(__uint128_t *ctr, unsigned char *key, unsigned char *output)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, NULL))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, output, &len, (const unsigned char *)ctr, sizeof(ctr)))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, output + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}