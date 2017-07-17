#ifndef _ENCRYPTKEYS_H_
#define _ENCRYPTKEYS_H_

#include <openssl/evp.h>

int encryptKeyFiles(char *path);

int decryptKeyFiles(char *path);

EVP_CIPHER_CTX *encryptKeyStreamSetup(char *keyFilePath);

#endif //_ENCRYPTKEYS_H_