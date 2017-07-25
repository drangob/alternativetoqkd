#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "pointerFile.h"
#include "openssl.h"
#include "libscrypt.h"

#define FILESIZE 100003840

//create a new pointer file
struct pointerFile *createPtrFile(char *dir) {
	//copy the data into the ptr
	struct pointerFile *ptr = malloc(sizeof(struct pointerFile));
	strcpy(ptr->dirPath, dir);
	strcpy(ptr->filename, "nextAvailable.ptr");
	ptr->currentFile = 0;
	ptr->byteOffset = 0;

	int saltlength = 16;
	getKey(ptr->salt, saltlength);

	//we need to set a password
	printf("Please enter a password to lock down the keys.\n");
	char password[100];
	scanf("%s", password);
	int passwordlength = strlen(password);

	//convert the password into an scrypt key
	unsigned char scryptKey[16];
	libscrypt_scrypt(password, passwordlength, ptr->salt, saltlength, SCRYPT_N, SCRYPT_r, SCRYPT_p, scryptKey, 16);

	//generate k2 and encrypt it
	unsigned char k2[16];
	getKey(k2, 16);
	//use salt || state as AD
	char associatedData[28];
	memcpy(associatedData, ptr->salt, saltlength);
	memcpy(associatedData+saltlength, &ptr->currentFile, sizeof(uint32_t));
	memcpy(associatedData+saltlength+sizeof(uint32_t), &ptr->byteOffset, sizeof(uint64_t));

	unsigned char nonce[12];
	packPtrFile(ptr, nonce);

	//outputs
	unsigned char ciphertext[200];
	unsigned char mac[16];

	int ciphertextLen = aes_gcm_encrypt(k2, 16, associatedData, 28, scryptKey, nonce, ciphertext, mac);

	//work out what to save the pointer as
	char ptrSavePath[167];
	sprintf(ptrSavePath, "%s/%s", ptr->dirPath, ptr->filename);
	//open up the file
	FILE *fd = fopen(ptrSavePath, "wb");

	//check for write error
	if(fd == NULL){
		printf("%s\n", ptrSavePath);
		perror("Opening pointerFile for saving failed");
		return NULL;
	}

	//fill in all the data 
	if( fwrite(ptr->salt, sizeof(char), 16, fd) != 16 ||
		fwrite(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
	    fwrite(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1  ||
		fwrite(ciphertext, ciphertextLen, 1, fd) != 1 ||
		fwrite(mac, 16, 1, fd) != 1 ) {

		puts("Could not write ptr");
		return NULL;
	}

	fclose(fd);
	return ptr;
}

//create a struct from a existing file
struct pointerFile *readPtrFile(char *dir, char *filename) {
	struct pointerFile *ptr = malloc(sizeof(struct pointerFile));
	//copy the dir to the struct
	strcpy(ptr->dirPath, dir);
	//copy the filename to the struct
	strcpy(ptr->filename, filename);
	//turn the dir and filename into full path
	char filePath[267];
	sprintf(filePath, "%s/%s", dir, ptr->filename);
	//printf("Using path %s\n", ptr->dirPath);

	FILE *fd = fopen(filePath, "rb");


	//read the ptr and put into struct
	//if fails show error
	if( fread(ptr->salt, sizeof(char), 16, fd) != 16 ||
		fread(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
		fread(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1 ) {

		puts("Could not read data from pointer.");
		exit(1);
		return NULL;

	}
	//printf("Read: %s offset = %u\n", ptr->dirPath, ptr->byteOffset);
	return ptr;
}

//update a ptr file from its struct 
struct pointerFile *updatePtrFile(struct pointerFile *ptr) {
	char filePath[267];
	sprintf(filePath, "%s/%s", ptr->dirPath, ptr->filename);

	//setup write into file
	FILE *fd = fopen(filePath, "wb");

	if( fwrite(ptr->salt, sizeof(char), 16, fd) != 16 ||
		fwrite(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
		fwrite(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1 ) {

		puts("Could not write data to pointer.");
		return NULL;
	}

	//printf("Wrote: %s offset = %u\n", ptr->dirPath, ptr->byteOffset);

	return ptr;
}

struct pointerFile *incrementPtrFile(struct pointerFile *ptr, uint64_t increment) {
	//pointer file must increment in blocks of 16
	if (increment % 16 != 0) {
		increment = increment - (increment % 16);
		increment+=16;
	}

	//if the current offset plus the increment is larger than the file
	//move the ptr to the next file
	if(ptr->byteOffset + increment > FILESIZE){
		//work out how many more bytes we need to move along
		uint64_t overflowBytes = increment - (FILESIZE - ptr->byteOffset);
		//get integer val of amount of files we are filling up
		int filledFiles = (overflowBytes / FILESIZE) + 1;
		//get the offset into the new file
		ptr->byteOffset = overflowBytes % FILESIZE;
		//move the ptr to a new file
		ptr->currentFile+=filledFiles;
	} else {
		//if we are all good just increment the counter
		ptr->byteOffset += increment;
	}
	updatePtrFile(ptr);
}

int packPtrFile(struct pointerFile *ptr, unsigned char output[12]) {
	memcpy(output, &ptr->currentFile, sizeof(uint32_t));
	memcpy(output+sizeof(uint32_t),&ptr->byteOffset, sizeof(uint64_t));
}

int verifyPtrFile(struct pointerFile *ptr) {
	char pointerPath[200];
	sprintf(pointerPath, "%s/%s", ptr->dirPath, ptr->filename);

	FILE *fd = fopen(pointerPath, "r");
	fseek(fd, 0L, SEEK_END);
	int fileSize = ftell(fd);
	rewind(fd);


	//read the char in
	unsigned char salt[16];
	fread(salt, 16, 1, fd);

	//scrypt to get the key
	printf("Please enter a password to verifyPtrFile.\n");
	char password[100];
	scanf("%s", password);
	int passwordlength = strlen(password);
	unsigned char scryptKey[16];
	libscrypt_scrypt(password, passwordlength, salt, 16, SCRYPT_N, SCRYPT_r, SCRYPT_p, scryptKey, 16);

	//read in the nonce
	unsigned char nonce[12];
	fread(nonce, 12, 1, fd);

	//create associatedData
	int associatedDataLength = 16 + 12;
	unsigned char *associatedData = malloc(associatedDataLength);
	memcpy(associatedData, salt, 16);
	memcpy(associatedData+16, nonce, 16);


	//work out how big the ciphertext is 
	int ciphertext_len = fileSize - 16 - 12 - 16;
	unsigned char *ciphertext = malloc(ciphertext_len);
	fread(ciphertext, ciphertext_len, 1, fd);

	unsigned char mac[16];
	fread(mac, 16, 1, fd);

	unsigned char k2[16];


	if(aes_gcm_decrypt(ciphertext, ciphertext_len, associatedData, associatedDataLength, mac, scryptKey, nonce, k2)){
		printf("The pointer is valid\n");
	} else {
		exit(-1);
	}

	free(associatedData);
	free(ciphertext);
}