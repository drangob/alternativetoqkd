#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <unistd.h>

#include "openssl.h"


uint32_t getFileSize(FILE *fd) {
	fseek(fd, 0L, SEEK_END);
	return ftell(fd);
}

unsigned char *crypto(char *path, char inputKey[16]) {
	//open the file for reading and writing
	FILE *fd = fopen(path, "r");
	
	//if we fail to open return
	if(fd == NULL) return NULL;

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

	return key;
}

int encryptKeyFiles(char *path) {
	char outputFile[250] = "";
	sprintf(outputFile, "%s/keys", path);
	FILE *fd = fopen(outputFile,"wb");

	char keyFileName[275] = "";

	char *outputKey;
	//infinite loop
	for (int i = 0; i > -1; ++i) {
		//get the key file names
		sprintf(keyFileName, "%s/%d.bin", path, i);
		printf("%s\n", keyFileName);
		outputKey = crypto(keyFileName, NULL);
		if(outputKey == NULL) break;
		printf("%s\n", outputKey);
		fwrite(outputKey, 16, 1, fd);
		free(outputKey);
	}
}

	


int decryptKeyFiles(char *path, char *key) {
	crypto(path, key);	
}


int main(int argc, char *argv[]) {
	int isDecrypt = -1;
	puts("encrypt(0) of decrypt(1)?");
	while (!(isDecrypt==0 || isDecrypt==1)){
		scanf("%d", &isDecrypt);
	}
	
	puts("What is the path of your randoms?");
	char path[250];
	scanf("%s", path);

	if(isDecrypt){

	} else {
		encryptKeyFiles(path);
	}



	


}
