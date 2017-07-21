#include <string.h>

#include "openssl.h"

int main(int argc, char const *argv[]) {
	unsigned char key[32] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	unsigned char inputString[] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus rhoncus dignissim tempor. Duis efficitur sit amet risus vel ultricies. Duis fringilla, nisl ut rutrum dignissim, metus nisi auctor odio, at dapibus ex est vestibulum ligula. Duis metus.";
	uint32_t len= 250;
	int outputLen;
	unsigned char output[500];
	AEAD_AES_128_CBC_HMAC_SHA_256_ENCRYPT(key, inputString, len, output, &outputLen);

	fwrite(output, outputLen, 1, stdout);
	puts("");

	unsigned char finalOutput[500];
	int finalOutLen = 0;

	AEAD_AES_128_CBC_HMAC_SHA_256_DECRYPT(key, output, outputLen, finalOutput, &finalOutLen);

	fwrite(finalOutput, finalOutLen, 1, stdout);
	puts("");

	return 0;
}