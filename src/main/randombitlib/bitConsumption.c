#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>

#include "pointerFile.h"
#include "encryptKeys.h"
#include "bitConsumption.h"

int shred(char *filename, int upToByte) {
	if (fork() == 0) {//if we are the fork
		char bytes[10];
		sprintf(bytes, "%u", upToByte);
		execl("/usr/bin/shred", "/usr/bin/shred", filename, "-z", "-s", bytes, NULL);
	} else {
		wait(NULL);
		return 0;
	}
}

uint32_t getFileSize(FILE *fd) {
	fseek(fd, 0L, SEEK_END);
	uint32_t size = ftell(fd);
	rewind(fd);
	return size;
}

//use this instead of memset 0 as aggressive compilers may render it insecure
int secureMemoryWipe(void *ptr, size_t len) {
	unsigned char *a = ptr;
	while(len--) *a = '\0';
	free(ptr);
}

//opens into memory and decrypts they key file
char *openFile(char *filename) {
	FILE *fd = fopen(filename, "rb");
	if(fd == NULL) {
		printf("%s. ", filename);
		perror("Opening file to read into memory failed.");
		exit(1);
	}
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


char *getBytes(char *path, struct pointerFile *ptr, uint32_t numOfBytes) {
	//get the current file out of the ptr file
	char curFileName[267];
	sprintf(curFileName, "%s/%u.bin", path, ptr->currentFile);

	//get the size of the keyfile
	FILE *fd = fopen(curFileName, "r");
	if(fd == NULL) {
		printf("%s. ", curFileName);
		perror("Opening file failed");
		exit(-1);
	}

	uint32_t keyFileSize = getFileSize(fd);
	fclose(fd);

	//calculate if we overspill into other files
	int usedFiles = numOfBytes / keyFileSize;
	int leftoverOffset = numOfBytes % keyFileSize;


	//we need a big buffer to put the bytes into when read
	char *outputBytes = malloc(numOfBytes);
	uint32_t usedOutputBytes = 0;
	uint32_t remainingRequiredBytes = numOfBytes;

	//for each file we need to read into read it
	for (int i = 0; i <= usedFiles; ++i) {
		//new file name is ptr + for loop iteration
		sprintf(curFileName, "%s/%u.bin", path, ptr->currentFile + i);		
		//read the file into memory
		char *keyFileContents = openFile(curFileName);
		//check for shredded file contents
		if (!memcmp(keyFileContents+ptr->byteOffset, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) {
			printf("You are most likely reading from shredded data, as a result this process will abort.\n");
			exit(-1);
		}

		if(!verifyPtrFile(ptr)) exit(-1);
		
		unsigned char k2[16];
		doGCMDecrypt(ptr, k2);
		//decrypt the file in memory
		cryptFileBuffer(k2, keyFileContents, keyFileSize, ptr->currentFile + i, path);

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
		//copy to the correct part of the output, some output from a keyfile, max num of available required bytes
		memcpy(&outputBytes[usedOutputBytes], &keyFileContents[sourceOffset], numOfBytesToCopy);
		//move a pointer along to count where we are in output
		usedOutputBytes += numOfBytesToCopy;

		//Securely wipe the decrypted file from memory.

		secureMemoryWipe(keyFileContents, keyFileSize);

		//shred to zero on the bits we just used
		shred(curFileName, sourceOffset + numOfBytesToCopy);
	}
	//inrement here so we can integrity protect it
	incrementPtrFile(ptr, numOfBytes);
	//scryptLogout(ptr);
	return outputBytes;
}

char *getBytesWithFastForward(char *path, struct pointerFile *ptr, uint32_t numOfBytes, uint32_t fileNumber, uint32_t offset) {
	if(fastForwardPtr(ptr, fileNumber, offset)) exit(-1);
	return getBytes(path, ptr, numOfBytes);
}