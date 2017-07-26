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

int encryptKeyFiles(char *path) {
	char outputFile[250] = "";
	sprintf(outputFile, "%s/keys", path);
	FILE *fd = fopen(outputFile,"wb");

	char keyFileName[275] = "";

	char *outputKey;
	//infinite loop until we cant read a file 
	for (int i = 0; i > -1; ++i) {
		//get the key file names
		sprintf(keyFileName, "%s/%d.bin", path, i);
		outputKey = crypto(keyFileName, NULL);
		if(outputKey == NULL) {
			free(outputKey);
			break;
		}
		//printf("%s\n", outputKey);
		fwrite(outputKey, 16, 1, fd);
		free(outputKey);
	}

	fclose(fd);
}

	


int decryptKeyFiles(char *path) {
	char inputFile[250] = "";
	sprintf(inputFile, "%s/keys", path);

	FILE *fd = fopen(inputFile, "r");
	char decryptKey[16];
	char *outputKey;

	char keyFileName[275] = "";

	for (int i = 0; i > -1; i++) {
		sprintf(keyFileName, "%s/%d.bin", path, i);
		fread(decryptKey, 16, 1, fd);
		outputKey = crypto(keyFileName, decryptKey);
		if(outputKey == NULL) {
			free(outputKey);
			break;
		}
	}

	fclose(fd);
}

EVP_CIPHER_CTX *encryptKeyStreamSetup(char *keyFilePath) {
	//setup the keystream context and save the key
	unsigned char keyStreamInitKey[16] = "";
	EVP_CIPHER_CTX *context = setupCTR(keyStreamInitKey, NULL);

	//open the file to save the keys
	char outputFile[250] = "";
	sprintf(outputFile, "%s/keys", keyFilePath);
	
	FILE *fd = fopen(outputFile, "a");

	if(fd == NULL) {
		perror("Opening encryption keys failed");
		exit(-1);
	}

	if(fwrite(keyStreamInitKey, 16, 1, fd) != 1) {
		perror("Writing encryption key failed");
		exit(-1);
	}
	fclose(fd);

	return context;
}

int lockDownKeys(char *keyFilePath, int isEncrypt, struct pointerFile *ptr) {
	char inputFile[250] = "";
	sprintf(inputFile, "%s/keys", keyFilePath);

	FILE *fd = fopen(inputFile, "r");
	uint32_t fileSize = getFileSize(fd);
	rewind(fd);
	//read the entire file into memory
	char *fileContents = malloc(fileSize);
	fread(fileContents, fileSize, 1, fd);
	//close and reopen for writing
	fclose(fd);

	if (isEncrypt) {
		puts("Please enter a password to lock down the keys.");
	} else {
		puts("Please enter a password to unlock the keys.");
	}
	
	char password[50];
	scanf("%s", password);
	int passwordlength = strlen(password);

	//get the salt from the library if it does not exist
	char salt[32];
	int saltlength = 32;
	char saltFile[250] = "";
	sprintf(saltFile, "%s/salt", keyFilePath);

	FILE *saltFd = fopen(saltFile, "r+");
	//if the file does not exist we make one
	if (saltFd == NULL) {
		libscrypt_salt_gen(salt, 32);
		saltFd = fopen(saltFile, "w");
		fwrite(salt, saltlength, 1, saltFd);
	} else { //if it existed we read it
		fread(salt, saltlength, 1, saltFd);
	}
	fclose(saltFd);

	//output of scrypt
	unsigned char key[32];
	libscrypt_scrypt(password, passwordlength, salt, saltlength, SCRYPT_N, SCRYPT_r, SCRYPT_p, key, 32);

	//get the additional data for hmac
	unsigned char ptrData[7];
	//packPtrFile(ptr, ptrData); 

	//setup output
	char *newFileContents = malloc(fileSize+32);
	uint32_t newFileSize = 0;

	if (isEncrypt) {
	} else {
	}
	
	free(newFileContents);
}


int lockKeys(char *keyFilePath, struct pointerFile *ptr) {
	lockDownKeys(keyFilePath, 1, ptr);
}

int unlockKeys(char *keyFilePath, struct pointerFile *ptr) {
	lockDownKeys(keyFilePath, 0, ptr);
}

int cryptFileBuffer(char *fileContents, uint32_t contentsSize, int fileNumber, char *path) {
	
	char keyFilePath[250] = "";
	sprintf(keyFilePath, "%s/keys", path);
	//open up the file of decryption keys
	FILE *fd = fopen(keyFilePath, "rb");
	if(fd == NULL) {
		perror("Opening key file failed.");
	}
	//seek to the correct key for decryption of the file buffer
	fseek(fd, fileNumber * 16, SEEK_SET);
	//read they key
	unsigned char key[16];
	fread(key, 16, 1, fd);
	fclose(fd);

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