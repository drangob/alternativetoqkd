#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "encryptKeys.h"
#include "pointerFile.h"
#include "openssl.h"
#include "bitGeneration.h"

int main(int argc, char const *argv[]) {
	uint32_t fileSize;

	char path[150];
	char ptrPath[150];
	printf("Please enter the full path of the directory for storage.\nENSURE THAT THIS IS EXT4 AND JOURNALLING IS DISABLED.\n");
	scanf("%s", path);


	printf("Would you like to store your state file off disk? y/n\n");
	char ptrChoice = ' ';
	while(!(ptrChoice == 'y' | ptrChoice == 'n')) {
		scanf(" %c", &ptrChoice);	
	}
	if (ptrChoice == 'y') {
		printf("Please enter the path where you want to save your state.\n");
		scanf("%s", ptrPath);
	} else {
		strcpy(ptrPath, path);
	}



	printf("Would you like to do simultaneous writing to two disks? y/n\n");
	char choice = ' ';
	while(!(choice == 'y' | choice == 'n')) {
		scanf(" %c", &choice);	
	}


	char secondaryPath[150];
	char secondaryPtrPath[150];
	if (choice == 'y') {
		printf("Please enter the path of the secondary directory.\n");
		scanf("%s", secondaryPath);	
		if (ptrChoice == 'y') {
			printf("Please enter the path where you want to save your secondary state.\n");
			scanf("%s", secondaryPtrPath);
		} else {
			strcpy(secondaryPtrPath, secondaryPath);
		}
	} else {
		secondaryPath[0] = '\0';
	}
	
	//get amount of data to generate
	uint32_t chunksNo = 0;
	printf("Please enter how many ~100mb chunks of data you desire\n");
	scanf("%u", &chunksNo);
	if (chunksNo == 0){
		printf("0 is not enough data. Please request more data.\n");
		return -1;
	}


	fileSize = LARGEBYTES;
	generateChunks(path, ptrPath, chunksNo, fileSize, secondaryPath, secondaryPath);
	

	return 0;
}
