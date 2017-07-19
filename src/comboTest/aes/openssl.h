#ifndef _OPENSSH_H_
#define _OPENSSH_H_

#include <stdint.h>
#include <openssl/evp.h>

int nextRand(EVP_CIPHER_CTX *context, unsigned char *output);

int encrypt(EVP_CIPHER_CTX *context, unsigned char *output);
EVP_CIPHER_CTX *sslSetup(unsigned char keyOut[16], unsigned char keyIn[16]);
int sslClose(EVP_CIPHER_CTX *context);
void errorHandling(char *str);

void rekey(EVP_CIPHER_CTX *context);


int cfbEncrypt(unsigned char keyIn[32], unsigned char *input, uint32_t inputSize, unsigned char *output);
int cfbDecrypt(unsigned char keyIn[32], unsigned char *input, uint32_t inputSize, unsigned char *output);


#endif //_OPENSSH_H_
