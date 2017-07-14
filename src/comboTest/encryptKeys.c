#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <sys/time.h>

#include "bitGeneration.h"
#include "openssl.h"
#include "encryptKeys.h"


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
		context = sslSetup(key, NULL);
	} else { //if there is a key we use it
		context = sslSetup(key, inputKey);
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

	//close reader without flushing
	sslClose(context);

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
	unsigned char keyStreamInitKey[16];
	EVP_CIPHER_CTX *context = sslSetup(keyStreamInitKey, NULL);

	//open the file to save the keys
	char outputFile[250] = "";
	sprintf(outputFile, "%s/keys", keyFilePath);
	FILE *fd = fopen(outputFile, "a");
	fwrite(keyStreamInitKey, 16, 1, fd);
	fclose(fd);

	return context;
}

// int main(int argc, char *argv[]) {
// 	int isDecrypt = -1;
// 	puts("encrypt(0) of decrypt(1)?");
// 	while (!(isDecrypt==0 || isDecrypt==1)){
// 		scanf("%d", &isDecrypt);
// 	}
	
// 	puts("What is the path of your randoms?");
// 	char path[250];
// 	scanf("%s", path);

// 	if(isDecrypt){
// 		decryptKeyFiles(path);
// 	} else {
// 		encryptKeyFiles(path);
// 	}
// }
