#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "pointerFile.h"
#include "encryptKeys.h"

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
	uint32_t size = ftell(fd);
	rewind(fd);
	return size;
}

//opens into memory and decrypts they key file
char *openFile(char *filename) {
	FILE *fd = fopen(filename, "rb");
	uint32_t fileSize = getFileSize(fd);
	//read the entire filecontents to a string
	char *fileContents = malloc(fileSize);
	if(fread(fileContents, 1, fileSize, fd) < fileSize) {
		printf("Reading file to memory didnt work.\n");
		exit(-1);
	}
	fclose(fd);
	return fileContents;
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

char *getBytes(char *path, struct pointerFile *ptr, uint32_t numOfBytes) {
	//get the current file out of the ptr file
	char curFileName[267];
	sprintf(curFileName, "%s/%u.bin", ptr->dirPath, ptr->currentFile);

	//get the size of the keyfile
	FILE *fd = fopen(curFileName, "r");
	uint32_t keyFileSize = getFileSize(fd);
	fclose(fd);

	//calculate if we overspill into other files
	int usedFiles = numOfBytes / keyFileSize;
	int leftoverOffset = numOfBytes % keyFileSize;

	//we are about to start reading files - we need access to the keys to decrypt them
	unlockKeys(path, ptr);

	//we need a big buffer to put the bytes into when read
	char *outputBytes = malloc(numOfBytes);
	uint32_t usedOutputBytes = 0;
	uint32_t remainingRequiredBytes = numOfBytes;

	//for each file we need to read into read it
	for (int i = 0; i <= usedFiles; ++i) {
		//new file name is ptr + for loop iteration
		sprintf(curFileName, "%s/%u.bin", ptr->dirPath, ptr->currentFile + i);		
		//read the file into memory
		char *keyFileContents = openFile(curFileName);
		//check for shredded file contents
		if (!memcmp(keyFileContents+ptr->byteOffset, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) {
			printf("You are most likely reading from shredded data, as a result this process will abort.\n");
			exit(-1);
		}

		//decrypt the file in memory
		cryptFileBuffer(keyFileContents, keyFileSize, ptr->currentFile + i, path);

		//if this is the first file then we need to copy from an offset
		int sourceOffset = 0;
		if(ptr->currentFile + i == ptr->currentFile) {
			sourceOffset = ptr->byteOffset;
		}
		//calculate the amount of bytes we can copy
		int numOfBytesToCopy = 0;
		if(remainingRequiredBytes > keyFileSize) {
			numOfBytesToCopy = keyFileSize;
			remainingRequiredBytes = remainingRequiredBytes - keyFileSize;
		} else {
			numOfBytesToCopy = remainingRequiredBytes;
			remainingRequiredBytes = 0;
		}
		//copy to the correct part of the output, some output from a keyfile, max num of availible required bytes
		memcpy(&outputBytes[usedOutputBytes], &keyFileContents[sourceOffset], numOfBytesToCopy);
		//move a pointer along to count where we are in output
		usedOutputBytes += numOfBytesToCopy;

		//free up the memory used by holding a whole file in memory
		free(keyFileContents);

		//shred to zero on the bits we just used
		shred(curFileName, sourceOffset + numOfBytesToCopy);
	}
	//inrement here so we can integrity protect it
	incrementPtrFile(ptr, numOfBytes);
	lockKeys(path, ptr);
	return outputBytes;

}

int main(int argc, char const *argv[]) {
	puts("What is the path for your randoms?");
	char path[267];
	scanf("%s", path);

	//open the ptr
	struct pointerFile *ptr = readPtrFile(path, "nextAvailible.ptr");
	if(ptr == NULL) {
		perror("Could not read pointer");
		return -1;
	}

	int isOTP = 0;

	if(isOTP){
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

		incrementPtrFile(ptr, fileSize);

	} else {
		puts("How many bytes do you want to read?");
		uint32_t bytesAmt;
		scanf("%d", &bytesAmt);

		

		void *resulting = getBytes(path, ptr, bytesAmt);

		
		char savepath[250];
		sprintf(savepath, "%s/output.bin", path);
		FILE *saveFile = fopen(savepath, "wb");
		fwrite(resulting, 1, bytesAmt, saveFile);
		fclose(saveFile);

	}

	



}	