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
		strcpy(keyOut, key);
	}

	// Create context and setup
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

int cfbEncrypt(unsigned char keyIn[32], unsigned char *input, uint32_t inputSize, unsigned char *output) {
	int len = 0;
	int len2 = 0;
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	EVP_CIPHER_CTX *context; // = malloc(sizeof(EVP_CIPHER_CTX));
	if(!(context = EVP_CIPHER_CTX_new())) {
		errorHandling("Context");
	}

	if(1 != EVP_EncryptInit(context, EVP_aes_256_cfb(), keyIn, "dontusethisinput")) {
		errorHandling("EncryptInit");
	}
	if(1 != EVP_EncryptUpdate(context, output, &len, input, inputSize)) {
		errorHandling("CFB Encrypt");
	}

	EVP_EncryptFinal(context, output + len , &len2);
	
	return 1;
}

int cfbDecrypt(unsigned char keyIn[32], unsigned char *input, uint32_t inputSize, unsigned char *output) {
	int len = 0;
	int len2 = 0;
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	EVP_CIPHER_CTX *context; // = malloc(sizeof(EVP_CIPHER_CTX));
	if(!(context = EVP_CIPHER_CTX_new())) {
		errorHandling("Context");
	}

	if(1 != EVP_DecryptInit(context, EVP_aes_256_cfb(), keyIn, "dontusethisinput")) {
		errorHandling("EncryptInit");
	}
	if(1 != EVP_DecryptUpdate(context, output, &len, input, inputSize)) {
		errorHandling("CFB Encrypt");
	}

	EVP_DecryptFinal(context, output + len , &len2);
	
	return 1;
}

unsigned char *padding(unsigned char *input, uint32_t inputSize) {
	//if it is not a multiple of 16 we must pad
	unsigned char PS[16];
	int remainder = inputSize % 16;

	if(remainder==15){memcpy(PS,"\x01",1);} else
    if(remainder==14){memcpy(PS,"\x02\x02",2);} else                           
    if(remainder==13){memcpy(PS,"\x03\x03\x03",3);} else                         
    if(remainder==12){memcpy(PS,"\x04\x04\x04\x04",4);} else                       
    if(remainder==11){memcpy(PS,"\x05\x05\x05\x05\x05",5);} else                     
    if(remainder==10){memcpy(PS,"\x06\x06\x06\x06\x06\x06",6);} else                   
	if(remainder== 9){memcpy(PS,"\x07\x07\x07\x07\x07\x07\x07",7);} else                 
    if(remainder== 8){memcpy(PS,"\x08\x08\x08\x08\x08\x08\x08\x08",8);} else               
    if(remainder== 7){memcpy(PS,"\x09\x09\x09\x09\x09\x09\x09\x09\x09",9);} else             
    if(remainder== 6){memcpy(PS,"\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A\x0A",10);} else           
	if(remainder== 5){memcpy(PS,"\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B",11);} else         
	if(remainder== 4){memcpy(PS,"\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C",12);} else       
    if(remainder== 3){memcpy(PS,"\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D\x0D",13);} else    
    if(remainder== 2){memcpy(PS,"\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E\x0E",14);} else  
	if(remainder== 1){memcpy(PS,"\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F\x0F",15);} else
    if(remainder== 0){memcpy(PS,"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",16);}

    //allocate the input with space for padding
    char *P = malloc(inputSize + remainder);
    //copy the data into a new buffer and pad it
    memcpy(P, input, inputSize);
    memcpy(&P[inputSize], PS,  16 - remainder);
	
    //free up the old one 
 
    return P;
}

unsigned char* hmac_sha256(const void *key, int keylen,
                           const unsigned char *data, int datalen,
                           unsigned char *result, unsigned int* resultlen) 
{
    return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

int AEAD_AES_128_CBC_HMAC_SHA_256_ENCRYPT(unsigned char key[32], unsigned char *input, uint32_t inputSize, unsigned char *output, int *outputLen) {

	unsigned char encKey[16];
	memcpy(encKey, key+16, 16);
	//make context
	EVP_CIPHER_CTX *cbcCtx;
	if(!(cbcCtx = EVP_CIPHER_CTX_new())) {
		errorHandling("Context");
	}
	//setup CBC
	if(1 != EVP_EncryptInit(cbcCtx, EVP_aes_128_cbc(), encKey, "dontusethisinput")) {
		errorHandling("EncryptInit");
	}

	//encrypt and place output
	char *paddedInput = padding(input, inputSize);
	int paddedSize = (16 - (inputSize % 16)) + inputSize;
	
	int sLen;
	unsigned char *s = malloc(inputSize);
	if(1 != EVP_EncryptUpdate(cbcCtx, s, &sLen, paddedInput, paddedSize)) {
		errorHandling("CFB Encrypt");
	}
	int len2;
	EVP_EncryptFinal(cbcCtx, s + sLen , &len2);

	EVP_CIPHER_CTX_free(cbcCtx);
	

	unsigned char hmacKey[16];
	memcpy(hmacKey, key, 16);

	char *A = "associatedData";
	//associated data size in bits
	uint64_t AL = htonll(strlen(A)*8);

	int hmacInputSize = strlen(A) + sLen + sizeof(uint64_t);
	unsigned char *hmacInput = malloc(hmacInputSize);
	
	memcpy(hmacInput, A, strlen(A));
	memcpy(&hmacInput[strlen(A)], s, sLen);
	memcpy(&hmacInput[strlen(A)+sLen], &AL, sizeof(uint64_t));

	hmac_sha256(hmacKey, 16, hmacInput, hmacInputSize, output, outputLen);

	//printf("Output len %i\n", hmacOutputLen);
	//printf("Output %s\n", hmacOutput);
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

	 // gettimeofday(&tv2, NULL);
	 // struct timeval tvdiff = { tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec };
	 // if (tvdiff.tv_usec < 0) { tvdiff.tv_usec += 1000000; tvdiff.tv_sec -= 1; }

	 // if (tvdiff.tv_usec > 000150) {
	 // 	printf("----rekey took %ld.%06ld\n", tvdiff.tv_sec, tvdiff.tv_usec);
	 // } else {
	 // 	printf("rekey took %ld.%06ld\n", tvdiff.tv_sec, tvdiff.tv_usec);	
	 // }
}
