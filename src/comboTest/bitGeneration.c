#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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
#define REKEYBYTES 1000000

uint32_t getFileSize(FILE *fd) {
	fseek(fd, 0L, SEEK_END);
	uint32_t size = ftell(fd);
	rewind(fd);
	return size;
}

int copyFile(char *destPath, char *srcPath) {
    FILE *fdDest, *fdSrc;
    int byte;
    //if we fail either exit
    if ((fdDest = fopen(destPath, "w")) && (fdSrc = fopen(srcPath, "r"))) {
    	//while we can read bytes, put them in the dest
        while ((byte = getc(fdSrc)) != EOF) putc(byte, fdDest);
        fclose(fdDest);
        fclose(fdSrc);

        return 0;
    }
    perror("File copy failed");
    printf("dest: %s\n", destPath);
    printf("src: %s\n", srcPath);
    return -1;
}

int writeFile(char *outputFile, uint32_t fileSize, EVP_CIPHER_CTX *keystreamContext, EVP_CIPHER_CTX *cipherContext, char *secondOutputFile) {

	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);


	FILE *fd = fopen(outputFile,"wb");
	if (fd == NULL) {
		perror("Opening file failed.");
		exit(-1);
	}


	//if a second file specified
	FILE *fd2;
	if (secondOutputFile[0] != '\0') {
		fd2 = fopen(secondOutputFile, "wb");
		if (fd2 == NULL) {
			perror("Opening second file failed");
			return -1;
		}
	}
	//128 bit output for aes
	unsigned char output[16];

	unsigned char cipher[16];

	//container for RDRAND randoms
	unsigned long long longRand = 0;

	//put the rekeys into per outputted 16 byte increments
	const unsigned int rekeysPerOutput = REKEYBYTES / 16;

	for (int i = 0; i < (fileSize / 16); i++) {
		//get the next random
		nextRand(keystreamContext, output);
		nextRand(cipherContext, cipher);


		//rekey at sensible interval 
		if (i % rekeysPerOutput == 0) {
			rekeyCTR(keystreamContext);
		} 

		//get random twice - because the aes output is 128 bits
		for (int i = 0; i < 2; i++) {
			_rdrand64_step(&longRand);
			//xor it
			output[i*7] = output[i*7] ^ longRand;

			//encrypt the data going into the output
			output[i*7] = output[i*7] ^ cipher[i*7];
		}

		if(fwrite(output, sizeof(unsigned char) * 16, 1, fd) != 1 ) {
			perror("Writing data failed.");
			exit(-1);
		}
		if(secondOutputFile[0] != '\0') {
			if(fwrite(output, sizeof(unsigned char) * 16, 1, fd2) != 1 ) {
				perror("Writing data failed.");
				exit(-1);
			}
		}
	}


	

	// double endTime = (double)clock()/CLOCKS_PER_SEC;
	gettimeofday(&tv2, NULL);
	// double timeElapsed = endTime - startTime;
	struct timeval tvdiff = { tv2.tv_sec - tv1.tv_sec, tv2.tv_usec - tv1.tv_usec };
	if (tvdiff.tv_usec < 0) { tvdiff.tv_usec += 1000000; tvdiff.tv_sec -= 1; }


	struct timeval tv3, tv4;
	gettimeofday(&tv3, NULL);

	fclose(fd);
	if (secondOutputFile[0] != '\0') fclose(fd2);

	gettimeofday(&tv4, NULL);
	struct timeval tvdiff2 = { tv4.tv_sec - tv3.tv_sec, tv4.tv_usec - tv3.tv_usec };
	if (tvdiff2.tv_usec < 0) { tvdiff2.tv_usec += 1000000; tvdiff2.tv_sec -= 1; }


	printf("Getting bytes took: %ld.%06ld : Writing to disk took: %ld.%06ld\n", tvdiff.tv_sec, tvdiff.tv_usec, tvdiff2.tv_sec, tvdiff2.tv_usec);

	return 0;
}

int generateChunks(char *path, char *ptrPath, uint32_t chunksNo, uint32_t fileSize, char *secondaryPath, char *secondaryPtrPath) {
	//creates a pointer file
	struct pointerFile *ptr = createPtrFile(ptrPath);
	verifyPtrFile(ptr);

	//write different files to consecutive file names
	char filename[150];
	char filename2[150];
	for (uint32_t i = 0; i < chunksNo; i++) {
		//create a new context for each file to effectively rekey per file
		EVP_CIPHER_CTX *context = setupCTR(NULL, NULL);
		//saves the key into the path

		unsigned char k2[16];
		doGCMDecrypt(ptr, k2);
		EVP_CIPHER_CTX *cipherContext = encryptKeyStreamSetup(path, i, k2);

		//edit the file name on each loop
		sprintf(filename, "%s/%u.bin", path, i);
		if (secondaryPath[0] != '\0') {
			sprintf(filename2, "%s/%u.bin", secondaryPath, i);
		} else {
			filename2[0] = '\0';
		}
		writeFile(filename, fileSize, context, cipherContext, filename2);

		cleanupContext(context);
		cleanupContext(cipherContext);
	}
	verifyPtrFile(ptr);
	scryptLogout(ptr);
	if (secondaryPath[0] != '\0') {
		char src[100], dest[100];
		sprintf(src, "%s/keys", path);
		sprintf(dest, "%s/keys", secondaryPath);
		copyFile(dest, src);
		sprintf(src, "%s/nextAvailable.ptr", ptrPath);
		sprintf(dest, "%s/nextAvailable.ptr", secondaryPtrPath);
		copyFile(dest, src);
	}
	free(ptr);
}

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
	generateChunks(path, ptrPath, chunksNo, fileSize, secondaryPath, secondaryPtrPath);
	

	return 0;
}
