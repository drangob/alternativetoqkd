#ifndef _POINTER_FILE_H_
#define _POINTER_FILE_H_

//struct for the state of the CSPRNG
struct pointerFile {
	//dir of the pointer file
	char dirPath[250];
	//filename of the pointer file
	char filename[25];
	//current file or dir
	uint16_t currentFile;
	//current offset into that file
	uint32_t byteOffset;
	//the mode being used, dir or file
	unsigned char mode;
	
};

//create a new pointer file
struct pointerFile *createPtrFile(char *dir, unsigned char mode);

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

int packPtrFile(struct pointerFile *ptr, unsigned char output[7]);

#endif //_POINTER_FILE_H_