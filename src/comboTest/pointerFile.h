#ifndef _POINTER_FILE_H_
#define _POINTER_FILE_H_

//struct for the state of the CSPRNG
struct pointerFile {
	//dir of the pointer file
	char dirPath[250];
	//filename of the pointer file
	char filename[25];
	//current file or dir
	uint32_t currentFile;
	//current offset into that file
	uint64_t byteOffset;
	//the salt of the password unlock operation
	unsigned char salt[16];
};

//create a new pointer file
struct pointerFile *createPtrFile(char *dir);

//create a struct from a existing file
struct pointerFile *readPtrFile(char *dir, char *filename);

//update a ptr file from its struct 
struct pointerFile *updatePtrFile(struct pointerFile *ptr); 

//when requesting bytes for encryption we increment the pointer file along
struct pointerFile *incrementPtrFile(struct pointerFile *ptr, uint64_t increment);

//we need to make a copy of the ptr for decryption
int mkPtrCopy(struct pointerFile *source, char *destName);

//saving pointers in own method is better for sanity
int savePtr(struct pointerFile *ptr);

int packPtrFile(struct pointerFile *ptr, unsigned char output[12]);

int verifyPtrFile(struct pointerFile *ptr);

#endif //_POINTER_FILE_H_