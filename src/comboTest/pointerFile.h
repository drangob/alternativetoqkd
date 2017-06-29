#ifndef _POINTER_FILE_H_
#define _POINTER_FILE_H_

//struct for the state of the CSPRNG
struct pointerFile {
	//file path
	char filePath[267];
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
struct pointerFile *readPtrFile(char *dir);

//update a ptr file from its struct 
struct pointerFile *updatePtrFile(struct pointerFile *ptr); 

//when requesting bytes for encryption we increment the pointer file along
struct pointerFile *incrementPtrFile(struct pointerFile *ptr, uint64_t increment);


#endif //_POINTER_FILE_H_