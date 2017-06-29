#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pointerFile.h"

#define FILESIZE 100003840

//create a new pointer file
struct pointerFile *createPtrFile(char *dir, unsigned char mode) {
	//create the save path
	char ptrSavePath[267];
	sprintf(ptrSavePath, "%s/nextAvailible.ptr", dir);
	//ptr file is made up of a file/folder name and offset from the start of that file/folder
	FILE *fd = fopen(ptrSavePath, "wb");
	uint16_t currentFile = 0;
	uint32_t byteNum = 0;

	//copy the data into the ptr
	struct pointerFile *ptr = malloc(sizeof(struct pointerFile));
	strcpy(ptr->filePath, ptrSavePath);
	ptr->currentFile = currentFile;
	ptr->byteOffset = byteNum;
	ptr->mode = mode;


	fwrite(&ptr->currentFile, sizeof(ptr->currentFile), 1, fd);
	fwrite(&ptr->byteOffset, sizeof(ptr->byteOffset), 1, fd);
	fwrite(&mode, sizeof(mode), 1, fd);

	fclose(fd);

	return ptr;
}

//create a struct from a existing file
struct pointerFile *readPtrFile(char *dir) {
	struct pointerFile *ptr = malloc(sizeof(struct pointerFile));
	//change the path to be directly to the pointer file

	sprintf(ptr->filePath, "%s/nextAvailible.ptr", dir);
	//printf("Using path %s\n", ptr->filePath);

	FILE *fd = fopen(ptr->filePath, "rb");


	//read the ptr and put into struct
	//if fails show error
	if( fread(&ptr->currentFile, sizeof(uint16_t), 1, fd) != 1 ||
		fread(&ptr->byteOffset, sizeof(uint32_t), 1, fd) != 1 ||
		fread(&ptr->mode, sizeof(unsigned char), 1, fd) != 1) {

		puts("Could not read data from pointer.");
		exit(1);
		return NULL;

	}
	//printf("Read: %s offset = %u\n", ptr->filePath, ptr->byteOffset);
	return ptr;
}

//update a ptr file from its struct 
struct pointerFile *updatePtrFile(struct pointerFile *ptr) {
	//setup write into file
	FILE *fd = fopen(ptr->filePath, "wb");

	if( fwrite(&ptr->currentFile, sizeof(uint16_t), 1, fd) != 1 ||
		fwrite(&ptr->byteOffset, sizeof(uint32_t), 1, fd) != 1 ||
		fwrite(&ptr->byteOffset, sizeof(char), 1, fd) != 1) {

		puts("Could not write data to pointer.");
		return NULL;
	}

	//printf("Wrote: %s offset = %u\n", ptr->filePath, ptr->byteOffset);

	return ptr;
}

struct pointerFile *incrementPtrFile(struct pointerFile *ptr, uint64_t increment) {
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