#ifndef _ENCRYPTKEYS_H_
#define _ENCRYPTKEYS_H_

#include <openssl/evp.h>
#include "pointerFile.h"

EVP_CIPHER_CTX *encryptKeyStreamSetup(char *keyFilePath, int fileNumber, unsigned char *k2);

int cryptFileBuffer(unsigned char *k2, char *fileContents, uint32_t contentsSize, int fileNumber, char *path);

#endif //_ENCRYPTKEYS_H_