#ifndef _BIT_GENERATION_H_
#define _BIT_GENERATION_H_

#include <stdint.h>
#include <openssl/evp.h>

uint32_t getFileSize(FILE *fd);

int writeFile(char *outputFile, uint32_t fileSize, EVP_CIPHER_CTX *context, EVP_CIPHER_CTX *cipherContext);

int oneTimePadMode(char *path, uint32_t chunksNo, uint32_t fileSize);

int symmetricMode(char *path, uint32_t chunksNo, uint32_t fileSize);

int main(int argc, char const *argv[]);

#endif //_BIT_GENERATION_H_