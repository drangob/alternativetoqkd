#ifndef _BITCONSUMPTION_H_
#define _BITCONSUMPTION_H_

#include <stdio.h>
#include <stdint.h>

#include "pointerFile.h"


int shred(char *filename, int upToByte);

uint32_t getFileSize(FILE *fd);
//opens into memory and decrypts they key file
char *openFile(char *filename);


char *getBytes(char *path, struct pointerFile *ptr, uint32_t numOfBytes);
char *getBytesWithFastForward(char *path, struct pointerFile *ptr, uint32_t numOfBytes, uint32_t fileNumber, uint32_t offset);


#endif //_BITCONSUMPTION_H_