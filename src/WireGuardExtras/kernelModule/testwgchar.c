#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define PSK_LEN 32


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


int main() {
	int ret, fd;
	unsigned char *packedVector;
	int requiredLength = 44;//PSK_LEN + sizeof(uint32_t) + sizeof(uint64_t);
	unsigned char key[PSK_LEN] = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
	//open the device
	fd = open("/dev/wgchar", O_RDWR);             

	while(1){
		//need to get all of vector at once
		struct requestVector requestVec;
		packedVector = malloc(sizeof(struct requestVector));
		ret = read(fd, packedVector, sizeof(struct requestVector));

		if(ret == 0) break;

		int copyOffset = 0;
		memcpy(&requestVec.requestType, packedVector, sizeof(enum requestType));
		copyOffset += sizeof(enum requestType);
		memcpy(&requestVec.fileNum, packedVector + copyOffset, sizeof(uint32_t));
		copyOffset += sizeof(uint32_t);
		memcpy(&requestVec.byteOffset, packedVector + copyOffset, sizeof(uint64_t));

		free(packedVector);


		
		unsigned char reply[44] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

		if (requestVec.requestType == KEYANDSTATE) {
			printf("Kernel wants key and state!\n");
			write(fd, reply, requiredLength);
		} else {
			printf("Kernel wants key from state!\n");
			write(fd, reply, requiredLength);
		}
	}

	printf("Reading must have failed.\n");

	return 0;
}
