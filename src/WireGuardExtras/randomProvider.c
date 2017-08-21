#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pointerFile.h"
#include "bitConsumption.h"

enum requestType {
	KEYANDSTATE,
	KEYFROMSTATE
};
//request vector
struct requestVector {
	enum requestType requestType;
	uint32_t fileNum;
	uint64_t byteOffset;
};

int main(int argc, char const *argv[]) {
	puts("What is the path for your randoms?");
	char path[150];
	scanf("%s", path);

	if(access(path, R_OK)<0) {
		printf("Path entered cannot be read, does it exist?\n");
		exit(-1);
	}

	char ptrPath[150];
	printf("Is your state file stored off disk? y/n\n");
	char ptrChoice = ' ';
	while(!(ptrChoice == 'y' | ptrChoice == 'n')) {
		scanf(" %c", &ptrChoice);	
	}
	if (ptrChoice == 'y') {
		printf("Please enter the path where your state is saved.\n");
		scanf("%s", ptrPath);
	} else {
		strcpy(ptrPath, path);
	}

	if(access(ptrPath, R_OK)<0) {
		printf("Pointer path entered cannot be read, does it exist?\n");
		exit(-1);
	}

	//open the ptr
	struct pointerFile *ptr = readPtrFile(ptrPath, "nextAvailable.ptr");
	if(ptr == NULL) {
		perror("Could not read pointer");
		return -1;
	}

	uint32_t bytesAmt = 32;

	if(access("/dev/wgchar", W_OK)<0){
		printf("Cannot open the character device. Is it loaded? Do you have permissions?\n");
		exit(-1);
	}



	int ret, fd;
	unsigned char *packedVector;
	int requiredLength = 44;//PSK_LEN + sizeof(uint32_t) + sizeof(uint64_t);
	unsigned char *key;
	//open the device
	fd = open("/dev/wgchar", O_RDWR);             

	while(1){
		//need to get all of vector at once
		struct requestVector requestVec;
		packedVector = malloc(sizeof(struct requestVector));
		ret = read(fd, packedVector, sizeof(struct requestVector));

		fwrite(packedVector, sizeof(packedVector), 1, stdout);

		//if(ret == 0) break;

		int copyOffset = 0;
		memcpy(&requestVec.requestType, packedVector, sizeof(enum requestType));
		copyOffset += sizeof(enum requestType);
		memcpy(&requestVec.fileNum, packedVector + copyOffset, sizeof(uint32_t));
		copyOffset += sizeof(uint32_t);
		memcpy(&requestVec.byteOffset, packedVector + copyOffset, sizeof(uint64_t));

		free(packedVector);


		unsigned char reply[44];

		if (requestVec.requestType == KEYANDSTATE) {
			printf("Kernel wants key and state!\n");
			requestVec.fileNum = ptr->currentFile;
			requestVec.byteOffset = ptr->byteOffset;
			key = getBytes(path, ptr, bytesAmt);
		} else if (requestVec.requestType == KEYFROMSTATE) {
			printf("Kernel wants key from state!\n");
			key = getBytesWithFastForward(path, ptr, bytesAmt, requestVec.fileNum, requestVec.byteOffset);
		}


		memcpy(reply, key, 32);
		memcpy(reply+32, &requestVec.fileNum, sizeof(requestVec.fileNum));
		memcpy(reply+sizeof(requestVec.fileNum), &requestVec.byteOffset, sizeof(requestVec.byteOffset));
		write(fd, reply, requiredLength);
	}

	printf("Reading must have failed.\n");































		
}	