#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "openssl.h"


struct aesState *aesRandStartup(void){
	sslSetup();

	struct aesState *state = malloc(sizeof(struct aesState));
	printf("allocated struct\n");

	FILE *frand = fopen("/dev/random", "rb");

	//get the aes key and read into it
	fread(state->key, sizeof(char) * 16, 1, frand);

	//aes counter to be incremented from random
	fread(&state->ctr, sizeof(__uint128_t), 1, frand);

	//stop getting new random data for aes
	fclose(frand);

	printf("returning struct\n");
	return state;
}

int aesRandTeardown(struct aesState *state){
	sslClose();
	//free(state);
}

int nextRand(struct aesState *state, unsigned char *output) {
	encrypt(&state->ctr, state->key, output);
	state->ctr++;
}


int sslSetup(void) {
	//Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);	
	return 1;
}

int sslClose(void) {
	EVP_cleanup();
	ERR_free_strings();
	return 1;
}

void handleErrors(void) {
	printf("Error in encryption occurred.\n");
	exit(-1);
}

int encrypt(__uint128_t *ctr, unsigned char *key, unsigned char *output) {
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
