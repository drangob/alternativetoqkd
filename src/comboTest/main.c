#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>

#include "aes.h"

#define BYTES 100003840

int write(char *outputFile) {
	double startTime = (double)clock()/CLOCKS_PER_SEC;

	FILE *fd = fopen(outputFile,"wb");
	FILE *frand = fopen("/dev/random", "r");

	__uint128_t nonce;
	__uint128_t counter;

	//library needs 16 bytes 
	uint8_t input[16];
	uint8_t output[16];
	uint8_t key[16];


	//fill 16 bytes of the nonce and key
	fread(&nonce, 16, 1, frand);
	fread(&key, 16, 1, frand);
	//fill 16 bytes of the counter 
	fread(&counter, sizeof(counter), 1, frand);
	

	//stop getting new random data for aes
	fclose(frand);

	//container for RDRAND randoms
	unsigned long long longRand;


	for (int i = 0; i < (BYTES / 16); i++) {
		//input is nonce xor counter
		input[0] = nonce ^ counter;
		//increment counters
		counter++;

		AES128_ECB_encrypt(input, key, output);

		//get random twice - because the aes output is 128 bits
		for (int i = 0; i < 2; i++) {
			_rdrand64_step(&longRand);
			//xor it
			output[i*7] = output[i*7] ^ longRand;
		}

		fwrite(output, sizeof(output), 1, fd);
	}

	fclose(fd);

	double endTime = (double)clock()/CLOCKS_PER_SEC;

	double timeElapsed = endTime - startTime;

	printf("%d bytes Took %fs\n", BYTES, timeElapsed);

	return 0;
}

int mkPointerFile(char *dir) {
	//create the save path
	char ptrSavePath[267];
	sprintf(ptrSavePath, "%s/nextAvailible.ptr", dir);
	//ptr file is made up of a 15 char file name
	//followed by a byte number up to 100003840
	FILE *fd = fopen(ptrSavePath, "wb");
	char currentFile[15] = "0.bin";
	uint32_t byteNum = 0;

	fwrite(currentFile, sizeof(currentFile), 1, fd);
	fwrite(&byteNum, sizeof(byteNum), 1, fd);

	fclose(fd);
}

int main(int argc, char const *argv[]) {
	//get path
	char path[250];
	printf("Please enter the full path of the directory for storage\n");
	scanf("%s", path);
	//get amount of data to generate
	uint32_t chunksNo = 0;
	printf("Please enter how many ~100mb chunks of data you desire\n");
	scanf("%u", &chunksNo);

	//write different files to consecutile file names
	char filename[265];
	for (uint32_t i = 0; i < chunksNo; ++i) {
		printf(filename, "%s/%u.bin", path, i);
		//edit the file name on each loop
		sprintf(filename, "%s/%u.bin", path, i);
		printf("%s\n", filename);
		write(filename);
	}
	
	mkPointerFile(path);

	return 0;
}
