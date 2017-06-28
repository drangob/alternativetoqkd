#ifndef _OPENSSH_H_
#define _OPENSSH_H_

#include <stdint.h>

//struct for the state of the CSPRNG
struct aesState {
	unsigned char key[16];
	__uint128_t ctr;
};

struct aesState *aesRandStartup(void);
int aesRandTeardown(struct aesState *state);
int nextRand(struct aesState *state, unsigned char *output);

int encrypt(__uint128_t *ctr, unsigned char *key, unsigned char *output);
int sslSetup(void);
int sslClose(void);
void handleErrors(void);

#endif //_OPENSSH_H_
