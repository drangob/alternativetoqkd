#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "pointerFile.h"

#define BYTES 100003840

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
	
	struct pointerFile *ptr = readPtrFile(path);
	if(ptr == NULL) {
		perror("Could not read pointer");
		return -1;
	}

	incrementPtrFile(ptr, fileSize);

	return 0;
}