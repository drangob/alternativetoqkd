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


	int saltlength = 16;
	getKey(ptr->salt, saltlength);

	getKey(ptr->mac, saltlength);
	getKey(ptr->ciphertext, saltlength);


	ptr->currentFile = 0;
	ptr->byteOffset = 0;

	ptr->loggedin = 0;
	//generate k2
	unsigned char k2[16];
	getKey(k2, 16);

	doGCMEncrypt(ptr, k2);

	savePtr(ptr);

	return ptr;
}

int savePtr(struct pointerFile *ptr) {
	// if(!verifyPtrFile(ptr)){
	// 	fprintf(stderr, "Pointer file is in invalid state, please re-encrypt before saving.\n");
	// }

	//work out what to save the pointer as
	char ptrSavePath[167];
	sprintf(ptrSavePath, "%s/%s", ptr->dirPath, ptr->filename);
	//open up the file
	FILE *fd = fopen(ptrSavePath, "wb");

	//check for write error
	if(fd == NULL){
		printf("%s\n", ptrSavePath);
		perror("Opening pointerFile for saving failed");
		return 1;
	}

	//fill in all the data 
	if( fwrite(ptr->salt, sizeof(char), 16, fd) != 16 ||
		fwrite(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
	    fwrite(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1  ||
		fwrite(ptr->ciphertext, sizeof(char), 16, fd) != 16 ||
		fwrite(ptr->mac, sizeof(char), 16, fd) != 16 ) {

		puts("Could not write ptr");
		return 1;
	}
	fclose(fd);

	//scryptLogout(ptr);
	return 0;
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
	//ptr->scryptKey = NULL;
	ptr->loggedin = 0;


	FILE *fd = fopen(filePath, "rb");


	//read the ptr and put into struct
	//if fails show error
	if( fread(ptr->salt, sizeof(char), 16, fd) != 16 ||
		fread(&ptr->currentFile, sizeof(uint32_t), 1, fd) != 1 ||
		fread(&ptr->byteOffset, sizeof(uint64_t), 1, fd) != 1 ||
		fread(ptr->ciphertext, sizeof(char), 16, fd) != 16 ||
		fread(ptr->mac, sizeof(char), 16, fd) != 16) {

		puts("Could not read data from pointer.");
		exit(1);
		return NULL;

	}

	
	return ptr;
}

struct pointerFile *updatePtrFile(struct pointerFile *ptr){
	unsigned char k2[16];
	doGCMDecrypt(ptr, k2);
	doGCMEncrypt(ptr, k2);
	savePtr(ptr);

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

int getNonce(struct pointerFile *ptr, unsigned char output[12]) {
	memcpy(output, &ptr->currentFile, sizeof(uint32_t));
	memcpy(output+sizeof(uint32_t),&ptr->byteOffset, sizeof(uint64_t));
}

int scryptLogin(struct pointerFile *ptr) {
	//scrypt to get the key
	printf("Please enter password.\n");
	char password[100];
	scanf("%s", password);
	int passwordlength = strlen(password);
	libscrypt_scrypt(password, passwordlength, ptr->salt, 16, SCRYPT_N, SCRYPT_r, SCRYPT_p, ptr->scryptKey, 16);
	ptr->loggedin = 1;
}

int scryptLogout(struct pointerFile *ptr) {
	memcpy(ptr->scryptKey, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16);
	ptr->loggedin = 0;
}

int doGCMEncrypt(struct pointerFile *ptr, unsigned char *k2input) {	
	if(!ptr->loggedin) scryptLogin(ptr);

	unsigned char nonce[12];
	getNonce(ptr, nonce);

	//use salt || state as AD
	unsigned char associatedData[28];
	memcpy(associatedData, ptr->salt, 16);
	memcpy(associatedData+16, nonce, 12);

	unsigned char ciphertextOutput[16] = "";
	unsigned char macOutput[16] = "";

	int ciphertextLen = aes_gcm_encrypt(k2input, 16, associatedData, 28, ptr->scryptKey, nonce, ciphertextOutput, macOutput);

	printf("ciphertextLen %d\n", ciphertextLen);

	memmove(ptr->ciphertext, ciphertextOutput, 16);
	memmove(ptr->mac, macOutput, 16);

	return 0;
}

int doGCMDecrypt(struct pointerFile *ptr, unsigned char *k2out) {
	if(!ptr->loggedin) scryptLogin(ptr);

	//read in the nonce
	unsigned char nonce[12];
	getNonce(ptr, nonce);

	//create associatedData
	unsigned char associatedData[28];
	memcpy(associatedData, ptr->salt, 16);
	memcpy(associatedData+16, nonce, 12);

	int ciphertext_len = 16;
	unsigned char ciphertextInput[16];
	unsigned char macInput[16];

	memcpy(ciphertextInput, ptr->ciphertext, 16);
	memcpy(macInput, ptr->mac, 16);

	int ret = aes_gcm_decrypt(ptr->ciphertext, ciphertext_len, associatedData, 28, ptr->mac, ptr->scryptKey, nonce, k2out);

	return ret;
}

int verifyPtrFile(struct pointerFile *ptr) {
	unsigned char k2[16];
	if(doGCMDecrypt(ptr, k2)) {
		return 1;
	} else {
		fprintf(stderr, "Pointer integrity bad.\n");
		return 0;
	}
	
}

int getk2FromPtr(struct pointerFile *ptr, unsigned char *k2) {
	return doGCMDecrypt(ptr, k2);
}

