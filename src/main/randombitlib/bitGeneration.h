#ifndef _BIT_GENERATION_H_
#define _BIT_GENERATION_H_

#include <stdint.h>
#include <openssl/evp.h>

#define LARGEBYTES 100003840
#define REKEYBYTES 1000000

uint32_t getFileSize(FILE *fd);

//int writeFile(char *outputFile, uint32_t fileSize, EVP_CIPHER_CTX *context, EVP_CIPHER_CTX *cipherContext);

int generateChunks(char *path, char *ptrPath, uint32_t chunksNo, uint32_t fileSize, char *secondaryPath, char *secondaryPtrPath);

int main(int argc, char const *argv[]);

#endif //_BIT_GENERATION_H_
