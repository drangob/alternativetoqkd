#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <immintrin.h>

#include "aes.h"

#define BYTES 100003840

int main(int argc, char const *argv[]) {

	double startTime = (double)clock()/CLOCKS_PER_SEC;

	FILE *fd = fopen("data.bin","wb");
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
