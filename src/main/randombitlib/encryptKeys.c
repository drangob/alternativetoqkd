#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <sys/time.h>

#include "bitGeneration.h"
#include "openssl.h"
#include "encryptKeys.h"
#include "scrypt/libscrypt.h"
#include "pointerFile.h"


unsigned char *crypto(char *path, char inputKey[16]) {
	//open the file for reading and writing
	FILE *fd = fopen(path, "r");
	
	//if we fail to open return
	if(fd == NULL) return NULL;
	printf("Doing crypto job on: %s\n", path);

	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);

	FILE *fdw = fopen(path, "r+");


	//put key on the heap to return it
	unsigned char *key = malloc(sizeof(char)*16);

	EVP_CIPHER_CTX *context;

	//if there is no key we make one up
	if(inputKey == NULL) {	
		//use ssl to encrypt -- requesting the key
		context = setupCTR(key, NULL);
	} else { //if there is a key we use it
		context = setupCTR(key, inputKey);
	}
	//printf("Key: %s\n", key);
	
	uint32_t fileSize = getFileSize(fd);
	rewind(fd);


	unsigned char ctrKey[16];
	unsigned char rdByte;
	//loop through each key
	for(int i = 0; i < fileSize; i+=16) {
		//get the cipher to xor
		encrypt(context, ctrKey);
		//do byte by byte xor to stop overflows
		for(int j = 0; j < 16; j++) {
			fread(&rdByte, 1, 1, fd);
			rdByte = rdByte ^ ctrKey[j];
			fwrite(&rdByte, 1, 1, fdw);
			if(feof(fd)) break;
		}
	}
	//flush changes to file
	fclose(fdw);

	fclose(fd);

	cleanupContext(context);

	gettimeofday(&tv2, NULL);
	struct timeval tvdiff = { tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec };
	if (tvdiff.tv_usec < 0) { tvdiff.tv_usec += 1000000; tvdiff.tv_sec -= 1; }
	printf("Job took: %ld.%06lds\n", tvdiff.tv_sec, tvdiff.tv_usec);

	return key;
}


EVP_CIPHER_CTX *encryptKeyStreamSetup(char *keyFilePath, int fileNumber, unsigned char *k2) {
	//setup the keystream context and save the key
	unsigned char keyStreamInitKey[16] = "";
	EVP_CIPHER_CTX *context = setupCTR(keyStreamInitKey, NULL);

	//create nonce
	uint32_t nonce[3] = {0,0,fileNumber};


	unsigned char ciphertext[16];
	unsigned char mac[16];
	aes_gcm_encrypt(keyStreamInitKey, 16, NULL, 0, k2, (unsigned char *) nonce, ciphertext, mac);
	unsigned char outputbuf[32];
	memcpy(outputbuf, ciphertext, 16);
	memcpy(outputbuf+16, mac, 16);

	//open the file to save the keys
	char outputFile[250] = "";
	sprintf(outputFile, "%s/keys", keyFilePath);
	
	FILE *fd = fopen(outputFile, "w");
	fseek(fd, fileNumber * 32, SEEK_SET);

	if(fd == NULL) {
		perror("Opening encryption keys failed");
		exit(-1);
	}

	if(fwrite(outputbuf, 32, 1, fd) != 1) {
		perror("Writing encryption key failed");
		exit(-1);
	}
	fclose(fd);

	return context;
}


int cryptFileBuffer(unsigned char *k2, char *fileContents, uint32_t contentsSize, int fileNumber, char *path) {
	char keyFilePath[250] = "";
	sprintf(keyFilePath, "%s/keys", path);
	//open up the file of decryption keys
	FILE *fd = fopen(keyFilePath, "rb");
	if(fd == NULL) {
		perror("Opening key file failed.");
	}
	//seek to the correct key for decryption of the file buffer
	fseek(fd, fileNumber * 32, SEEK_SET);
	//read they key
	unsigned char ciphertext[32];
	fread(ciphertext, 32, 1, fd);
	fclose(fd);	

	uint32_t nonce[3] = {0,0,fileNumber};

	unsigned char key[16];

	if (aes_gcm_decrypt(ciphertext, 16, NULL, 0, ciphertext+16, k2, (unsigned char *) nonce, key) < 0){
		printf("Getting file key failed.\n");
		exit(-1);
	}

	EVP_CIPHER_CTX *context = setupCTR(NULL, key);	
	char ctrKey[16];
	//loop through the size of the file contents by 16 bytes each time
	for(int i = 0; i < contentsSize; i+=16) {
		//get the keystream 16 bytes
		encrypt(context, ctrKey);
		//do byte by byte xor 
		for(int j = 0; j < 16; j++) {
			//change each byte of the file contents 1 by 1
			fileContents[i+j] = fileContents[i+j] ^ ctrKey[j];
			//when we reach the end of the file break out of the loops
			if(i + j > contentsSize) break;
		}
	}
	cleanupContext(context);
}
