#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "pointerFile.h"
#include "openssl.h"

#define LARGEBYTES 100003840
#define SMALLBYTES 16384

int writeFile(char *outputFile, uint32_t fileSize, EVP_CIPHER_CTX *context) {
	//double startTime = (double)clock()/CLOCKS_PER_SEC;

	FILE *fd = fopen(outputFile,"wb");

	//128 bit output for aes
	unsigned char output[16];

	//container for RDRAND randoms
	unsigned long long longRand;

	for (int i = 0; i < (fileSize / 16); i++) {
		//get the next random
		encrypt(context, output);

		//get random twice - because the aes output is 128 bits
		for (int i = 0; i < 2; i++) {
			_rdrand64_step(&longRand);
			//xor it
			output[i*7] = output[i*7] ^ longRand;
		}

		fwrite(output, sizeof(unsigned char) * 16, 1, fd);
	}

	fclose(fd);

	// double endTime = (double)clock()/CLOCKS_PER_SEC;

	// double timeElapsed = endTime - startTime;

	// printf("%s: %d bytes Took %fs\n",outputFile, fileSize, timeElapsed);

	return 0;
}

int oneTimePadMode(char *path, uint32_t chunksNo, uint32_t fileSize) {
	createPtrFile(path, '0');

	//write different files to consecutive file names
	char filename[265];
	for (uint32_t i = 0; i < chunksNo; i++) {
		//create a new context each file to effectively swap out the key each time
		EVP_CIPHER_CTX *context = sslSetup();
		
		//edit the file name on each loop
		sprintf(filename, "%s/%u.bin", path, i);
		writeFile(filename, fileSize, context);
		sslClose(context);
	}
}


int symmetricMode(char *path, uint32_t chunksNo, uint32_t fileSize) {
	createPtrFile(path, '1');

	char foldername[265];
	//make the required number of folders
	for (int i = 0; i < chunksNo; ++i) {
		//create a new context for each folder, causing the keys to be rotated at that point
		EVP_CIPHER_CTX *context = sslSetup();

		sprintf(foldername, "%s/%u", path, i);
		mkdir(foldername, 0700);
		//write different files to consecutive file names
		char filename[265];
		for (uint32_t i = 0; i < 6104; i++) {
			//edit the file name on each loop
			sprintf(filename, "%s/%u.bin", foldername, i);
			writeFile(filename, fileSize, context);
		}
		sslClose(context);
	}
}

int main(int argc, char const *argv[]) {
	uint32_t fileSize;
	//changing the mode changes the file size and the layout of the files
	printf("Please choose a mode of operation:\n-One time pad mode  (0) \n-Symmetric key mode (1)\n");
	char mode = ' ';
	//loop until we get a mode
	while(!(mode == '0' || mode == '1')) {
		mode = getchar();
	}
	//get path
	char path[250];
	printf("Please enter the full path of the directory for storage.\n ENSURE THAT THIS IS EXT4 AND JOURNALLING IS DISABLED.");
	scanf("%s", path);
	//get amount of data to generate
	uint32_t chunksNo = 0;
	printf("Please enter how many ~100mb chunks of data you desire\n");
	scanf("%u", &chunksNo);


	if(mode == '0') {
		fileSize = LARGEBYTES;
		oneTimePadMode(path, chunksNo, fileSize);
	} else {
		fileSize = SMALLBYTES;
		symmetricMode(path, chunksNo, fileSize);
	}
	

	return 0;
}
