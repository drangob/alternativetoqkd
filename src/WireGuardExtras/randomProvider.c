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

	int wgchar = open("/dev/wgchar", O_WRONLY);
	unsigned char *key;

	//infite loop of sending the keys to wireguard
	//semaphores save us from this being a horrible idea
	while(1){
		//get the key
		key = getBytes(path, ptr, bytesAmt);
		//send it to wireguard
		write(wgchar, key, bytesAmt);
		printf("Sent key to wireguard!\n");
		free(key);
	}
	
}	