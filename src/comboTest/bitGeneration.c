#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "encryptKeys.h"
#include "pointerFile.h"
#include "openssl.h"
#include "bitGeneration.h"

#define LARGEBYTES 100003840
#define SMALLBYTES 16384
#define REKEYBYTES 100003840 / 300

uint32_t getFileSize(FILE *fd) {
	fseek(fd, 0L, SEEK_END);
	return ftell(fd);
}

int writeFile(char *outputFile, uint32_t fileSize, EVP_CIPHER_CTX *keystreamContext, EVP_CIPHER_CTX *cipherContext) {

	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);


	FILE *fd = fopen(outputFile,"wb");

	//128 bit output for aes
	unsigned char output[16];

	unsigned char cipher[16];

	//container for RDRAND randoms
	unsigned long long longRand;

	//put the rekeys into per outputted 16 byte increments
	const unsigned int rekeysPerOutput = REKEYBYTES / 16;

	for (int i = 0; i < (fileSize / 16); i++) {
		//get the next random
		nextRand(keystreamContext, output);
		nextRand(cipherContext, cipher);


		//rekey at sensible interval 
		if (i % rekeysPerOutput == 0) {
			rekey(keystreamContext);
		} 

		//get random twice - because the aes output is 128 bits
		for (int i = 0; i < 2; i++) {
			_rdrand64_step(&longRand);
			//xor it
			output[i*7] = output[i*7] ^ longRand;

			//encrypt the data going into the output
			output[i*7] = output[i*7] ^ cipher[i*7];
		}

		fwrite(output, sizeof(unsigned char) * 16, 1, fd);
	}


	

	// double endTime = (double)clock()/CLOCKS_PER_SEC;
	gettimeofday(&tv2, NULL);
	// double timeElapsed = endTime - startTime;
	struct timeval tvdiff = { tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec };
	if (tvdiff.tv_usec < 0) { tvdiff.tv_usec += 1000000; tvdiff.tv_sec -= 1; }


	printf("Getting bytes took %ld.%06ld\n", tvdiff.tv_sec, tvdiff.tv_usec);


	struct timeval tv3, tv4;
	gettimeofday(&tv3, NULL);

	fclose(fd);

	gettimeofday(&tv4, NULL);
	struct timeval tvdiff2 = { tv4.tv_sec - tv3.tv_sec, tv4.tv_usec - tv3.tv_usec };
	if (tvdiff2.tv_usec < 0) { tvdiff2.tv_usec += 1000000; tvdiff2.tv_sec -= 1; }
	printf("Writing to disk took %ld.%06ld\n", tvdiff2.tv_sec, tvdiff2.tv_usec);

	return 0;
}

int oneTimePadMode(char *path, uint32_t chunksNo, uint32_t fileSize) {
	createPtrFile(path, '0');

	//write different files to consecutive file names
	char filename[265];
	for (uint32_t i = 0; i < chunksNo; i++) {
		//create a new context each file to effectively swap out the key each time
		EVP_CIPHER_CTX *context = sslSetup(NULL, NULL);
		
		EVP_CIPHER_CTX *cipherContext = encryptKeyStreamSetup(path);

		//edit the file name on each loop
		sprintf(filename, "%s/%u.bin", path, i);

		writeFile(filename, fileSize, context, cipherContext);
		sslClose(context);
		sslClose(cipherContext);
	}
}


// int symmetricMode(char *path, uint32_t chunksNo, uint32_t fileSize) {
// 	createPtrFile(path, '1');

// 	char foldername[265];
// 	//make the required number of folders
// 	for (int i = 0; i < chunksNo; ++i) {
// 		//create a new context for each folder, causing the keys to be rotated at that point
// 		EVP_CIPHER_CTX *context = sslSetup(NULL, NULL);

// 		sprintf(foldername, "%s/%u", path, i);
// 		mkdir(foldername, 0700);
// 		//write different files to consecutive file names
// 		char filename[265];
// 		for (uint32_t i = 0; i < 6104; i++) {
// 			//edit the file name on each loop
// 			sprintf(filename, "%s/%u.bin", foldername, i);
// 			writeFile(filename, fileSize, context);
// 		}
// 		sslClose(context);
// 	}
// }

int main(int argc, char const *argv[]) {
	uint32_t fileSize;
	//changing the mode changes the file size and the layout of the files
	// printf("Please choose a mode of operation:\n-One time pad mode  (0) \n-Symmetric key mode (1)\n");
	// char mode = ' ';
	// //loop until we get a mode
	// while(!(mode == '0' || mode == '1')) {
	// 	mode = getchar();
	// }
	//get path
	char path[250];
	printf("Please enter the full path of the directory for storage.\n ENSURE THAT THIS IS EXT4 AND JOURNALLING IS DISABLED.\n");
	scanf("%s", path);
	//get amount of data to generate
	uint32_t chunksNo = 0;
	printf("Please enter how many ~100mb chunks of data you desire\n");
	scanf("%u", &chunksNo);


	// if(mode == '0') {
		fileSize = LARGEBYTES;
		oneTimePadMode(path, chunksNo, fileSize);
		//encryptKeyFiles(path);


	// } else {
	// 	fileSize = SMALLBYTES;
	// 	symmetricMode(path, chunksNo, fileSize);
	// }
	

	return 0;
}
