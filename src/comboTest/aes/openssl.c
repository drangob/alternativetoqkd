#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/time.h>

#include "openssl.h"

EVP_CIPHER_CTX *sslSetup(unsigned char keyOut[16], unsigned char keyIn[16]) {
	//Initialise the library
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	//define 128bit key and read into it
	unsigned char key[16];
	//if the user specifies a keyIn they want to provide a key for crypto
	if(keyIn != NULL) {
		memcpy(key, keyIn, 16);
	} else {
		FILE *devRandomfd = fopen("/dev/random", "rb");
		fread(key, 1, sizeof(char)*16, devRandomfd);
		fclose(devRandomfd);
	}

	//if the user has specified keyout then they want to preserve the key
	if(keyOut != NULL) {
		strcpy(keyOut, key);
	}

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

	 // struct timeval tv1, tv2;
	 // gettimeofday(&tv1, NULL);

	
	FILE *devRandomfd = fopen("/dev/random", "rb");

	//define 128bit key and read into it
	unsigned char key[16];
	if (fread(key, 1, sizeof(char)*16, devRandomfd)!=16){
		printf("Read bad\n");
		exit(1);
	}
	fclose(devRandomfd);

	if(1 != EVP_CipherInit_ex(context, EVP_aes_128_ctr(), NULL, key, NULL ,1)) {
		errorHandling("EncryptInit");
	}

	 // gettimeofday(&tv2, NULL);
	 // struct timeval tvdiff = { tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec };
	 // if (tvdiff.tv_usec < 0) { tvdiff.tv_usec += 1000000; tvdiff.tv_sec -= 1; }

	 // if (tvdiff.tv_usec > 000150) {
	 // 	printf("----rekey took %ld.%06ld\n", tvdiff.tv_sec, tvdiff.tv_usec);
	 // } else {
	 // 	printf("rekey took %ld.%06ld\n", tvdiff.tv_sec, tvdiff.tv_usec);	
	 // }
	 

}
