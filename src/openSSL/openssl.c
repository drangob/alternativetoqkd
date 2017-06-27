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
  EVP_CIPHER_CTX *context;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(context = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. 
     Provide context, type of encryption, unknown, key and IV
  */
  if(1 != EVP_EncryptInit_ex(context, EVP_aes_128_ecb(), NULL, key, NULL))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   */
  if(1 != EVP_EncryptUpdate(context, output, &len, (const unsigned char *)ctr, sizeof(__uint128_t)))
    handleErrors();
  ciphertext_len = len;

  /* Clean up */
  EVP_CIPHER_CTX_free(context);

  return ciphertext_len;
}