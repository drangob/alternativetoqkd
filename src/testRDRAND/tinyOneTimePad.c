#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>

int encrypt(char *input, char *output, unsigned long long key){
	//make a mask so we can encrypt each of the chars one by one
	unsigned char mask;
	//each char will be encrypted
	for (int i = 0; i < 7; i++) {
		//get the last 8 bits from the key
		mask = (key & 0xFF);
		//xor
		output[i] = input[i] ^ key;
		//shift the key along
		key = key >> 8;
	}
	return 0;
}

int main(int argc, char const *argv[]) {
	//get random numbers
	uint16_t shortRand = 0;
	_rdrand16_step(&shortRand);

	uint32_t intRand = 0;
	_rdrand32_step(&intRand);

	unsigned long long longRand = 0;
	_rdrand64_step(&longRand);

	//print random numbers
	printf("shortRand: %u\n", shortRand);
	printf("intRand: %u\n", intRand);
	printf("intRand: %llu\n", longRand);

	//make strings
	char string[8] = "";
	char crypt[8] = "";
	char decrypt[8] = "";

	FILE *outputFile = fopen("oneTimePad.txt" , "w+");

	//input
	scanf("%s",string);
	fprintf(outputFile, "%s\n", string);

	encrypt(string, crypt, longRand);
	printf("Crypted: %s\n", crypt);
	fprintf(outputFile, "%s\n", crypt);

	encrypt(crypt, decrypt, longRand);
	printf("Decrypted %s\n", decrypt);
	fprintf(outputFile, "%s\n", decrypt);

	fclose(outputFile);
	return 0;
}