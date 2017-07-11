#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include "openssl.h"

EVP_CIPHER_CTX *sslSetup(void) {
	//Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	FILE *devRandomfd = fopen("/dev/random", "rb");

	//define 128bit key and read into it
	unsigned char key[16];
	fread(key, sizeof(char) * 16, 1, devRandomfd);
	fclose(devRandomfd);

	// Create context and setup the ssl
	EVP_CIPHER_CTX *context = malloc(sizeof(EVP_CIPHER_CTX));
	if(!(context = EVP_CIPHER_CTX_new())) {
		errorHandling("Context");
	}
		
	if(1 != EVP_CipherInit_ex(context, EVP_aes_128_ctr(), NULL, key, NULL ,1)) {
		errorHandling("EncryptInit");
	}

	return context;
}

int sslClose(EVP_CIPHER_CTX *context) {
	EVP_cleanup();
	ERR_free_strings();

	// Clean up 
	EVP_CIPHER_CTX_free(context);
}

void errorHandling(char *str) {
	printf("Error in encryption occurred.\n Error was in: %s\n", str);
	exit(-1);
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


void rekey(EVP_CIPHER_CTX *context) {
	FILE *devRandomfd = fopen("/dev/random", "rb");

	//define 128bit key and read into it
	unsigned char key[16];
	fread(key, sizeof(char) * 16, 1, devRandomfd);
	fclose(devRandomfd);

	if(1 != EVP_CipherInit_ex(context, EVP_aes_128_ctr(), NULL, key, NULL ,1)) {
		errorHandling("EncryptInit");
	}

}