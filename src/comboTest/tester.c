#include <string.h>

#include "openssl.h"

int main(int argc, char const *argv[]) {
	unsigned char plaintext[] = "I am plaintext\0";
	int plaintext_len = 15;

	unsigned char associatedData[] = "";
	int associatedDataLength = 0;

	unsigned char key[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	unsigned char nonce[12] = "\0\0\0\0\0\0\0\0\0\0\0\0";

	unsigned char ciphertext[200] = "";

	unsigned char mac[16];

	int ciphertext_len = aes_gcm_encrypt(plaintext, plaintext_len, associatedData, associatedDataLength, key, nonce, ciphertext, mac);

	fwrite(plaintext, plaintext_len, 1, stdout);
	puts("");

	fwrite(ciphertext, ciphertext_len, 1, stdout);
	puts("");

	unsigned char newPlaintext[255];

	if(aes_gcm_decrypt(ciphertext, ciphertext_len, associatedData, associatedDataLength, mac, key, nonce, newPlaintext)) {
		puts("integrity good");
	}


	fwrite(newPlaintext, plaintext_len, 1, stdout);
	puts("");	

	return 0;
}