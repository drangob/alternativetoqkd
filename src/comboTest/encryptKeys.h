#ifndef _ENCRYPTKEYS_H_
#define _ENCRYPTKEYS_H_

#include <openssl/evp.h>
#include "pointerFile.h"

int encryptKeyFiles(char *path);

int decryptKeyFiles(char *path);

EVP_CIPHER_CTX *encryptKeyStreamSetup(char *keyFilePath);

//int lockDownKeys(char *keyFilePath, int isEncrypt);

int lockKeys(char *keyFilePath, struct pointerFile *ptr);

int unlockKeys(char *keyFilePath, struct pointerFile *ptr);

int cryptFileBuffer(char *fileContents, uint32_t contentsSize, int fileNumber, char *path);

#endif //_ENCRYPTKEYS_H_