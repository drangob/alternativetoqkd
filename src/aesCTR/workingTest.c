#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "aes.h"



int encrypt(__uint128_t *ctr, unsigned char *key, unsigned char *output);

void handleErrors(void){
  puts("Error occurred");
  exit(-1);
}

int openSSL(__uint128_t *_input, __uint128_t *_output) {
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

  
  ciphertext_len = encrypt (&ctr, key, output);
  *_input = ctr;
  *_output = output[0];
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


int tinyAES(__uint128_t *_input, __uint128_t *_output) {

	__uint128_t counter = 0;

	//library needs 16 bytes 
	uint8_t input[16];
	uint8_t output[16];
	/* A 128 bit key */
  	unsigned char *key = (unsigned char *)"0123456789012345";

	//encrypt 0 with 012345789012345
	AES128_ECB_encrypt((const unsigned char *)&counter, key, output);

	*_input = counter;
	*_output = (__uint128_t)output[0];
	return 0;
}





int main(int argc, char const *argv[]) {
	__uint128_t openSSLin, openSSLout;
	__uint128_t tinyAESin, tinyAESout;

	//provide containers for the input and output of openssl implementation
	openSSL(&openSSLin, &openSSLout);

	//provide containers for the input and output of tinyAES
	tinyAES(&tinyAESin, &tinyAESout);


	if(openSSLin == tinyAESin && openSSLout == tinyAESout)
		puts("all good!");
	return 0;
}
