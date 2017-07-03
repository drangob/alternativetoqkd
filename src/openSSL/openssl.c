#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define BYTES 100003840

int encrypt(EVP_CIPHER_CTX *context, unsigned char *output);

void errorHandling(char *str) {
	printf("Error in encryption occurred.\n Error was in: %s\n", str);
	exit(-1);
}

int sslSetup(EVP_CIPHER_CTX *context) {
	//Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);	

	FILE *fdRand = fopen("/dev/random", "rb");
	//define 128bit key and read into it
	unsigned char key[16];
	fread(key, sizeof(char) * 16, 1, fdRand);
	fclose(fdRand);

	if(1 != EVP_CipherInit_ex(context, EVP_aes_128_ctr(), NULL, key, NULL ,1)) {
		errorHandling("EncryptInit");
	}

}

int sslClose(EVP_CIPHER_CTX *context) {
	EVP_cleanup();
	ERR_free_strings();

	// Clean up 
	EVP_CIPHER_CTX_free(context);
}



int main (void) {
	double startTime = (double)clock()/CLOCKS_PER_SEC;

	
	FILE *fd = fopen("data.bin", "wb");




	// Create context 
	EVP_CIPHER_CTX *context;

	if(!(context = EVP_CIPHER_CTX_new())) {
		errorHandling("Context");
	}

	sslSetup(context);

	//output
	unsigned char output[16];

	int ciphertext_len;


	for (int i = 0; i < (BYTES / 16); i++) {
		ciphertext_len = encrypt(context, output);
		fwrite(output, ciphertext_len, 1, fd);
	}



	double endTime = (double)clock()/CLOCKS_PER_SEC;

	double timeElapsed = endTime - startTime;

	printf("%d bytes Took %fs\n", BYTES, timeElapsed);

	sslClose(context);
	return 0;
}


int encrypt(EVP_CIPHER_CTX *context, unsigned char *output) {
	int len;

	char plaintext[] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	
	
	//encrypt some nulls to get the  
	if(1 != EVP_CipherUpdate(context, output, &len, plaintext, sizeof(char)*16)){
		errorHandling("Encrypt Update");
	}

	//EVP_CipherFinal_ex(context, output, &len);

	return len;
}
