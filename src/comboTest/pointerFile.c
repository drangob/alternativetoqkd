#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pointerFile.h"

#define FILESIZE 100003840

//create a new pointer file
struct pointerFile *createPtrFile(char *dir) {
	//copy the data into the ptr
	struct pointerFile *ptr = malloc(sizeof(struct pointerFile));
	strcpy(ptr->dirPath, dir);
	strcpy(ptr->filename, "nextAvailible.ptr");
	ptr->currentFile = 0;
	ptr->byteOffset = 0;

	if (savePtr(ptr)){
		exit(-1);
	}

	return ptr;
}

int savePtr(struct pointerFile *ptr) {
	//work out what to save the pointer as
	char ptrSavePath[167];
	sprintf(ptrSavePath, "%s/%s", ptr->dirPath, ptr->filename);
	//open up the file
	FILE *fd = fopen(ptrSavePath, "wb");

	//check for write error
	if(fd == NULL){
		printf("%s\n", ptrSavePath);
		perror("Opening pointerFile for saving failed");
		return -1;
	}

	//fill in all the data 
	if( fwrite(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
	    fwrite(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1 ) {

		puts("Could not write ptr");
		return -1;
	}

	fclose(fd);
	return 0;
}

//create a struct from a existing file
struct pointerFile *readPtrFile(char *dir, char *filename) {
	struct pointerFile *ptr = malloc(sizeof(struct pointerFile));
	//copy the dir to the struct
	strcpy(ptr->dirPath, dir);
	//copy the filename to the struct
	strcpy(ptr->filename, filename);
	//turn the dir and filename into full path
	char filePath[267];
	sprintf(filePath, "%s/%s", dir, ptr->filename);
	//printf("Using path %s\n", ptr->dirPath);

	FILE *fd = fopen(filePath, "rb");


	//read the ptr and put into struct
	//if fails show error
	if( fread(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
		fread(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1 ) {

		puts("Could not read data from pointer.");
		exit(1);
		return NULL;

	}
	//printf("Read: %s offset = %u\n", ptr->dirPath, ptr->byteOffset);
	return ptr;
}

//update a ptr file from its struct 
struct pointerFile *updatePtrFile(struct pointerFile *ptr) {
	char filePath[267];
	sprintf(filePath, "%s/%s", ptr->dirPath, ptr->filename);

	//setup write into file
	FILE *fd = fopen(filePath, "wb");

	if( fwrite(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
		fwrite(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1 ) {

		puts("Could not write data to pointer.");
		return NULL;
	}

	//printf("Wrote: %s offset = %u\n", ptr->dirPath, ptr->byteOffset);

	return ptr;
}

struct pointerFile *incrementPtrFile(struct pointerFile *ptr, uint64_t increment) {
	//pointer file must increment in blocks of 16
	if (increment % 16 != 0) {
		increment = increment - (increment % 16);
		increment+=16;
	}

	//if the current offset plus the increment is larger than the file
	//move the ptr to the next file
	if(ptr->byteOffset + increment > FILESIZE){
		//work out how many more bytes we need to move along
		uint64_t overflowBytes = increment - (FILESIZE - ptr->byteOffset);
		//get integer val of amount of files we are filling up
		int filledFiles = (overflowBytes / FILESIZE) + 1;
		//get the offset into the new file
		ptr->byteOffset = overflowBytes % FILESIZE;
		//move the ptr to a new file
		ptr->currentFile+=filledFiles;
	} else {
		//if we are all good just increment the counter
		ptr->byteOffset += increment;
	}
	updatePtrFile(ptr);
}

int mkPtrCopy(struct pointerFile *source, char *destName) {

	struct pointerFile *dest = malloc(sizeof(struct pointerFile));

	strcpy(dest-> dirPath, source->dirPath);
	strcpy(dest->filename, destName);
	dest->currentFile = source->currentFile;
	//current offset into that file
	dest->byteOffset = source->byteOffset;

	savePtr(dest);

}

int packPtrFile(struct pointerFile *ptr, unsigned char output[7]) {
	memcpy(output, &ptr->currentFile, sizeof(uint32_t));
	memcpy(output+sizeof(uint32_t),&ptr->byteOffset, sizeof(uint64_t));
}