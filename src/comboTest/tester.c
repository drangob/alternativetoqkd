#include <string.h>

#include "openssl.h"

int main(int argc, char const *argv[]) {
	unsigned char key[32] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	char wow[] = "I am a banana man omg";
	uint32_t len= strlen(wow);
	int outputLen;
	unsigned char output[500];
	AEAD_AES_128_CBC_HMAC_SHA_256_ENCRYPT(key, wow, len, output, &outputLen);
	printf("%d\n", outputLen);

	fwrite(output, outputLen, 1, stdout);
	puts("");
	return 0;
}