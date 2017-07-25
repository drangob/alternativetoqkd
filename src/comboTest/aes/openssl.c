#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <sys/time.h>

#include "openssl.h"
#include "Quantis.h"

uint64_t htonll(uint64_t value)
{
    // The answer is 42
    static const int num = 42;

    // Check the endianness
    if (*(char*)&num == num)
    {
        const uint32_t high_part = htonl((uint32_t)(value >> 32));
        const uint32_t low_part = htonl((uint32_t)(value & 0xFFFFFFFFLL));

        return ((uint64_t)low_part << 32) | high_part;
    } else
    {
        return value;
    }
}

int nextRand(EVP_CIPHER_CTX *context, unsigned char *output){
	encrypt(context, output);
}


EVP_CIPHER_CTX *setupCTR(unsigned char keyOut[16], unsigned char keyIn[16]) {
	//Initialise the library

	//define 128bit key and read into it
	unsigned char key[16];
	//if the user specifies a keyIn they want to provide a key for crypto
	if(keyIn != NULL) {
		memcpy(key, keyIn, 16);
	} else {
		FILE *devRandomfd = fopen("/dev/random", "rb");
		fread(key, 1, sizeof(char)*16, devRandomfd);
		fclose(devRandomfd);
		//do quantis if we can
		unsigned char quantisKey[16];
		if( QuantisCount(QUANTIS_DEVICE_USB)){
			if(QuantisRead(QUANTIS_DEVICE_USB, 0, quantisKey, 16) != 16) errorHandling("QuantisRead");
			for (int i = 0; i < 16; i++) {
				key[i] = key[i] ^ quantisKey[i];
			}
		}
	}

	//if the user has specified keyout then they want to preserve the key
	if(keyOut != NULL) {
		memcpy(keyOut, key, 16);
	}

	// Create context and setup
	EVP_CIPHER_CTX *context;
	if(!(context = EVP_CIPHER_CTX_new())) {
		errorHandling("Context");
	}
		
	if(1 != EVP_CipherInit_ex(context, EVP_aes_128_ctr(), NULL, key, NULL ,1)) {
		errorHandling("EncryptInit");
	}

	return context;
}

int cleanupContext(EVP_CIPHER_CTX *context) {
	// Clean up 
	EVP_CIPHER_CTX_cleanup(context);
	free(context);
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





void rekeyCTR(EVP_CIPHER_CTX *context) {
	FILE *devRandomfd = fopen("/dev/random", "rb");

	//define 128bit key and read into it
	unsigned char key[16];
	if (fread(key, 1, sizeof(char)*16, devRandomfd)!=16){
		printf("Read bad\n");
		exit(1);
	}
	fclose(devRandomfd);


	unsigned char quantisKey[16];
	if( QuantisCount(QUANTIS_DEVICE_USB)){
		if(QuantisRead(QUANTIS_DEVICE_USB, 0, quantisKey, 16) != 16) errorHandling("QuantisRead");
		for (int i = 0; i < 16; i++) {
			key[i] = key[i] ^ quantisKey[i];
		}
	}

	if(1 != EVP_CipherInit_ex(context, EVP_aes_128_ctr(), NULL, key, NULL ,1)) {
		errorHandling("EncryptInit");
	}
}


int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *associatedData,
	int associatedDataLength, unsigned char *key, unsigned char *nonce,
	unsigned char *ciphertext, unsigned char *mac) {
	EVP_CIPHER_CTX *ctx;

	int len;
	int ciphertext_len;

	if(!(ctx = EVP_CIPHER_CTX_new())) errorHandling("Aes gcm Encrypt - context");

	// Initialise cipher
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)){
		errorHandling("Aes gcm encrypt - init");
	}

	// setup GCM with nonce of 96 bits
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)){
		errorHandling("aes_gcm_encrypt - setup nonce length");
	}

	 // Initialise key and nonce
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)){
		errorHandling("aes_gcm_encrypt- key and nonce");
	} 

	//add in the associated data.
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, associatedData, associatedDataLength)) {
		errorHandling("aes_gcm_encrypt - add associatedData");
	} 

	//Do the encryption of the text
	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
		errorHandling("aes_gcm_encrypt - do encryption");
	}
	ciphertext_len = len;

	//do final
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
		errorHandling("aes_gcm_encrypt - EncryptFinal");
	}
	ciphertext_len += len;

	// Get the mac 
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, mac)) {
		errorHandling("aes_gcm_encrypt - getting mac");
	}

	/* Clean up */
	cleanupContext(ctx);

	return ciphertext_len;
}

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *associatedData,
	int associatedDataLength, unsigned char *mac, unsigned char *key, unsigned char *nonce,
	unsigned char *plaintext) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	if(!(ctx = EVP_CIPHER_CTX_new())) {
		errorHandling("aes_gcm_decrypt - context");
	}

	/* Initialise the decryption operation. */
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
		errorHandling("aes_gcm_decrypt - init cipher");
	}

	/* Set IV length. Not necessary if this is 12 bytes (96 bits) */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) {
		errorHandling("aes_gcm_decrypt - ctrl cipher");
	}

	/* Initialise key and IV */
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
		errorHandling("aes_gcm_decrypt - init nonce & key");
	}

	//do associated data
	if(!EVP_DecryptUpdate(ctx, NULL, &len, associatedData, associatedDataLength)) {
		errorHandling("aes_gcm_decrypt - associatedData");
	}

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
		errorHandling("aes_gcm_decrypt - doing decryption");
	}

	plaintext_len = len;

	/* Set expected mac value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, mac)) {
		errorHandling("aes_gcm_decrypt - set mac");
	}

	//do encryption - positive return means it passed verification
	ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	/* Clean up */
	cleanupContext(ctx);

	if(ret > 0)
	{
		/* Success */
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}
