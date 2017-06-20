#include <time.h>
#include <stdio.h>


int main(int argc, char const *argv[]) {

	//predefine
	FILE *fd;
	double startTime;
	double endTime;
	double timeElapsed;
	char input[8];

	startTime = (double)clock()/CLOCKS_PER_SEC;

	fd = fopen("data.bin", "rb");

	//see to halfway through the file from the beginning
	fseek(fd, 50001920, SEEK_SET);

	//read 8 bytes
	fread(input, 8, 1, fd);

	endTime = (double)clock()/CLOCKS_PER_SEC;
	timeElapsed = endTime - startTime;

	printf("Random Access Took %fs\n", timeElapsed);

	return 0;
}