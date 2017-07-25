#ifndef _OPENSSH_H_
#define _OPENSSH_H_

#include <stdint.h>
#include <openssl/evp.h>

int nextRand(EVP_CIPHER_CTX *context, unsigned char *output);

int encrypt(EVP_CIPHER_CTX *context, unsigned char *output);
EVP_CIPHER_CTX *setupCTR(unsigned char keyOut[16], unsigned char keyIn[16]);
int cleanupContext(EVP_CIPHER_CTX *context);
void errorHandling(char *str);

void rekeyCTR(EVP_CIPHER_CTX *context);

int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *associatedData,
	int associatedDataLength, unsigned char *key, unsigned char *nonce,
	unsigned char *ciphertext, unsigned char *mac);

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *associatedData,
	int associatedDataLength, unsigned char *mac, unsigned char *key, unsigned char *nonce,
	unsigned char *plaintext);

#endif //_OPENSSH_H_
