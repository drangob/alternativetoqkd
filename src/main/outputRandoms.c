#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bitConsumption.h"
#include "pointerFile.h"

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

	//request some bytes and write them to a file.
	puts("How many bytes do you want to read?");
	uint32_t bytesAmt;
	scanf("%d", &bytesAmt);



	void *resulting = getBytes(path, ptr, bytesAmt); //getBytesWithFastForward(path, ptr, bytesAmt, 32, 32);

	if(resulting == NULL){
		exit(-1);
	}

	char savepath[250];
	sprintf(savepath, "%s/output.bin", path);
	FILE *saveFile = fopen(savepath, "wb");
	fwrite(resulting, 1, bytesAmt, saveFile);
	fclose(saveFile);

	free(resulting);
	scryptLogout(ptr);
	free(ptr);
}	