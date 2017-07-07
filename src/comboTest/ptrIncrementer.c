#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pointerFile.h"

#define SYMMETRIC_SIZE 16384

int shred(char *filename, int upToByte) {
	if (fork() == 0) {//if we are the fork
		printf("shredding!\n");
		char bytes[10];
		sprintf(bytes, "%u", upToByte);
		execl("/usr/bin/shred", "/usr/bin/shred", filename, "-z", "-s", bytes, NULL);
	} else {
		wait(NULL);
		return 0;
	}
}


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
	uint16_t keyNum = ptr->currentFile;

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

	fclose(fdKey);
	fclose(newCipher);

	//do shredding
	//if there is overspill then we need to do multiple files
	if(ptr->byteOffset + fileSize > keyFileSize) {
		//calculate the files we have used up completely
		int usedFiles = fileSize / keyFileSize;
		int leftoverOffset = fileSize % keyFileSize;
		//for each file we've filled, shred the whole thing
		int i = ptr->currentFile;
		for (; i < usedFiles; ++i) {
			char fileToShred[270];
			sprintf(fileToShred, "%s/%u.bin", ptr->dirPath, i);
			shred(fileToShred, keyFileSize);
		}
		//shred into the last file
		i++;
		char fileToShred[270];
		sprintf(fileToShred, "%s/%u.bin", ptr->dirPath, i);
		shred(fileToShred, leftoverOffset);
	} else { //we didnt overspill - easy shredding
		shred(cryptoPath, ptr->byteOffset + fileSize);
	}

	
}

void saveSymmetricKey(struct pointerFile *ptr, unsigned int keySize, char *saveLoc) {
	unsigned int keySizeInBytes = keySize / 8;
	//calculate which file we need to look into 
	unsigned int filenum = ptr->byteOffset / SYMMETRIC_SIZE;
	unsigned int fileOffset = ptr->byteOffset % SYMMETRIC_SIZE;
	//if we want to overspill into the next file, just error for now
	if(fileOffset + keySizeInBytes > SYMMETRIC_SIZE) {
		printf("Key too big- dying now\n");
		exit(-1);
	}
	char sourcePath[270];
	//open the desired file at th desired offset

	sprintf(sourcePath, "%s/%u/%u.bin", ptr->dirPath, ptr->currentFile, filenum);
	FILE *sourceFd = fopen(sourcePath, "rb");
	if(sourceFd == NULL) perror("Opening src failed");
	fseek(sourceFd, fileOffset, SEEK_SET);

	//allocate a buffer for the key and read the key
	unsigned char *key = malloc(sizeof(char) * keySizeInBytes);
	fread(key, keySizeInBytes, 1, sourceFd);

	fclose(sourceFd);

	FILE *saveFd = fopen(saveLoc, "wb");
	if(saveFd == NULL) perror("Opening dest failed");	
	fwrite(key, keySizeInBytes, 1, saveFd);

	fclose(saveFd);


	// shred up to where we now are
	shred(sourcePath, (ptr->byteOffset + keySizeInBytes));

}

int main(int argc, char const *argv[]) {
	puts("What is the path for your randoms?");
	char path[267];
	scanf("%s", path);

	char modeChoice = ' ';
	puts("is oneTimePad? Y/N");
	while(! (modeChoice == 'Y' || modeChoice == 'N') ){
		scanf("%c", &modeChoice);
	}

	int isOTP = 0;
	if (modeChoice == 'Y') isOTP = 1;

	//open the ptr
	struct pointerFile *ptr = readPtrFile(path, "nextAvailible.ptr");
	if(ptr == NULL) {
		perror("Could not read pointer");
		return -1;
	}


	if(isOTP == 1) {
		char fileToCrypt[267];
		puts("Please enter the path of yourfile to encrypt");
		scanf("%s", fileToCrypt);
		FILE *inputFile = fopen(fileToCrypt, "rb");

		uint32_t fileSize = getFileSize(inputFile);

		printf("file to crypt size %u\n", fileSize);
		//encrypt
		oneTimePad(ptr, inputFile, fileSize, "crypted");


		//decrypt
		mkPtrCopy(ptr, "decrypt.ptr");


		////now we are shredding this is like not useful to test

		// FILE *cipherTextIn = fopen("crypted", "rb");
		// fileSize = getFileSize(cipherTextIn);
		// printf("File to decryt size %u\n", fileSize);
		// oneTimePad(ptr, cipherTextIn, fileSize, "decrypted.txt");

		incrementPtrFile(ptr, fileSize);
	} else {
		saveSymmetricKey(ptr, 256, "/mnt/randomUSB/key.bin");
		incrementPtrFile(ptr, 32);

	}
	

	



}	