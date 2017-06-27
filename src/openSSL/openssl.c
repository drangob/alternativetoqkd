#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define BYTES 100003840


int encrypt(__uint128_t *ctr, unsigned char *key, unsigned char *output);

int sslSetup(void) {
	//Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);	
}

int sslClose(void) {
	EVP_cleanup();
	ERR_free_strings();
}

void handleErrors(void){
	printf("Error in encryption occurred.\n");
	exit(-1);
}

int main (void) {
	sslSetup();


	double startTime = (double)clock()/CLOCKS_PER_SEC;

	FILE *fdRand = fopen("/dev/random", "rb");
	FILE *fd = fopen("data.bin", "wb");

	//define 128bit key and read into it
	unsigned char key[16];
	fread(key, sizeof(char) * 16, 1, fdRand);

	//128 bit counter to be incremented from random
	__uint128_t ctr = 0;
	fread(&ctr, sizeof(__uint128_t), 1, fdRand);

	fclose(fdRand);

	//output
	unsigned char output[16];

	int ciphertext_len;


	for (int i = 0; i < (BYTES / 16); i++) {
		ciphertext_len = encrypt (&ctr, key, output);
		ctr++;
		fwrite(output, ciphertext_len, 1, fd);
	}

	double endTime = (double)clock()/CLOCKS_PER_SEC;

	double timeElapsed = endTime - startTime;

	printf("%d bytes Took %fs\n", BYTES, timeElapsed);

	sslClose();
	return 0;
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
