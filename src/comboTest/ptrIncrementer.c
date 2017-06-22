#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define BYTES 100003840

int nextFile(char *curFile, int increment);

int readPtr(FILE *fd, char *curFile, uint32_t *bytes) {
	rewind(fd);
	//read the ptr and put into files
	//if fails show error
	if( fread(curFile, 15, 1, fd) != 1 ||
		fread(bytes, sizeof(*bytes), 1, fd) != 1) {
		puts("Could not read data from pointer.");
		return -1;
	}
	printf("Read: %s %u\n", curFile, *bytes);
	return 0;
}

int updatePtr(FILE *fd, char *curFile, uint32_t *bytes, uint64_t increment) {
	//if the current offset plus the increment is larger than the file
	//move the ptr to the next file
	if(*bytes + increment > BYTES){
		//work out how many more bytes we need to move along
		uint64_t overflowBytes = increment - (BYTES - *bytes);
		//get integer val of amount of files we are filling up
		int filledFiles = (overflowBytes / BYTES) + 1;
		//get the offset into the new file
		*bytes = overflowBytes % BYTES;

		nextFile(curFile, filledFiles);
	} else {
		*bytes += increment;
	}

	rewind(fd);
	//save the ptr
	fwrite(curFile, 15, 1, fd);
	fwrite(bytes, sizeof(bytes), 1, fd);
}

int nextFile(char *curFile, int increment){
	//move to the next file
	int fileNum;
	for (int i = 0; i < increment; ++i) {
		sscanf(curFile, "%u.bin", &fileNum);
		fileNum++;
		sprintf(curFile, "%u.bin", fileNum);
	}
	return 0;
}

int main(int argc, char const *argv[]) {
	puts("What is the path for your randoms?");
	char path[267];
	scanf("%s", path);
	//get file size
	puts("Please enter the size of your file in bytes");
	uint64_t fileSize = 0;
	if(scanf("%lu", &fileSize) != 1) {
		puts("Invalid size");
		return -1;
	}

	//open the ptr
	sprintf(path, "%s/nextAvailible.ptr", path);
	FILE *ptrFd = fopen(path, "r+b");
	if(ptrFd == NULL) {
		perror("Could not read pointer");
		return -1;
	}


	char ptrFile[15];
	uint32_t bytesOffset;
	readPtr(ptrFd, ptrFile, &bytesOffset);

	updatePtr(ptrFd, ptrFile, &bytesOffset, fileSize);

	readPtr(ptrFd, ptrFile, &bytesOffset);

	return 0;
}