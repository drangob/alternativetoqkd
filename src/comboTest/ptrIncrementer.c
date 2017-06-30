#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pointerFile.h"

unsigned char oneTimePadReadByte(FILE *fd, uint32_t fileSize, struct pointerFile *ptr, uint16_t *keyNum) {
	unsigned char output;
	if(ftell(fd) < fileSize) {
		//printf("reading a byte WITHOUT overflow\n");
	} else {
		fclose(fd);

		*keyNum += 1;

		char keyPath[267];
		sprintf(keyPath, "%s/%u.bin", ptr->dirPath, *keyNum);
		fd = fopen(keyPath, "rb");
	}
	fread(&output, sizeof(char), 1, fd);
	return output;
}


uint32_t getFileSize(FILE *fd) {
	fseek(fd, 0L, SEEK_END);
	return ftell(fd);
}

int oneTimePad(struct pointerFile *ptr, FILE *fd, uint32_t fileSize, char *outputname) {
	//rewind the file
	rewind(fd);

	//open the pointed to file
	char cryptoPath[267];
	sprintf(cryptoPath, "%s/%u.bin", ptr->dirPath, ptr->currentFile);

	FILE *fdKey = fopen(cryptoPath, "rb");
	uint32_t keyFileSize = getFileSize(fdKey);
	rewind(fdKey);

	//seek to the correct part of the key
	fseek(fdKey, ptr->byteOffset, SEEK_SET);

	//keynum in case it needs incrementing on read
	uint16_t keyNum = 0; 
	keyNum = ptr->currentFile;

	unsigned char inputByte;
	unsigned char keyByte;
	unsigned char cipherByte;

	FILE *newCipher = fopen(outputname, "wb");

	for(uint32_t i = 0; i < fileSize; i++) {
		fread(&inputByte, sizeof(char), 1, fd);
		keyByte = oneTimePadReadByte(fdKey, keyFileSize, ptr, &keyNum);
		//fread(&keyByte, sizeof(char), 1, fdKey);
		cipherByte = inputByte ^ keyByte;
		fwrite(&cipherByte, sizeof(char), 1, newCipher);
	}

	printf("printed all the bits\n");

	fclose(fdKey);
	fclose(newCipher);
}

int main(int argc, char const *argv[]) {
	puts("What is the path for your randoms?");
	char path[267];
	scanf("%s", path);

	char fileToCrypt[267];
	puts("Please enter the path of yourfile to encrypt");
	scanf("%s", fileToCrypt);
	FILE *inputFile = fopen(fileToCrypt, "rb");

	uint32_t fileSize = getFileSize(inputFile);

	printf("file to crypt size %u\n", fileSize);

	// //get file size
	// puts("Please enter the size of your file in bytes");
	// uint64_t fileSize = 0;
	// if(scanf("%lu", &fileSize) != 1) {
	// 	puts("Invalid size");
	// 	return -1;
	// }

	//open the ptr
	struct pointerFile *ptr = readPtrFile(path, "nextAvailible.ptr");
	if(ptr == NULL) {
		perror("Could not read pointer");
		return -1;
	}

	//encrypt
	oneTimePad(ptr, inputFile, fileSize, "crypted");


	//decrypt
	mkPtrCopy(ptr, "decrypt.ptr");

	FILE *cipherTextIn = fopen("crypted", "rb");
	fileSize = getFileSize(cipherTextIn);
	printf("File to decryt size %u\n", fileSize);
	oneTimePad(ptr, cipherTextIn, fileSize, "decrypted.txt");



	incrementPtrFile(ptr, fileSize);


	return 0;
}