#ifndef _OPENSSH_H_
#define _OPENSSH_H_

#include <stdint.h>

int nextRand(EVP_CIPHER_CTX *context, unsigned char *output);

int encrypt(EVP_CIPHER_CTX *context, unsigned char *output);
EVP_CIPHER_CTX *sslSetup(void);
int sslClose(EVP_CIPHER_CTX *context);
void errorHandling(char *str);

#endif //_OPENSSH_H_
