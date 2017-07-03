#include <time.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>

#define BYTES 100000000

int main(int argc, char const *argv[]) {

	double startTime = (double)clock()/CLOCKS_PER_SEC;

	//create binary file
	FILE *fd = fopen("data.bin","wb");

	unsigned long long longRand;

	//generate however many bytes we require and write them to a file
	for (int i = 0; i < BYTES * 8 ; i+=64) {
		_rdrand64_step(&longRand);
		fwrite(&longRand, sizeof(longRand), 1, fd);	
	}


	double endTime = (double)clock()/CLOCKS_PER_SEC;

	double timeElapsed = endTime - startTime;

	printf("Took %fs\n", timeElapsed);

	return 0;
}
