#include <string.h>

#include "openssl.h"
#include "pointerFile.h"

int main(int argc, char const *argv[]) {
	unsigned char plaintext[] = "I am plaintext\0";
	int plaintext_len = 15;


	unsigned char key[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	unsigned char nonce[16] = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	unsigned char ciphertext[200] = "";

	unsigned char mac[16];

	int ciphertext_len = aes_gcm_encrypt(plaintext, plaintext_len, NULL, 0, key, nonce, ciphertext, mac);

	fwrite(plaintext, plaintext_len, 1, stdout);
	puts("");

	fwrite(ciphertext, ciphertext_len, 1, stdout);
	puts("");

	unsigned char newPlaintext[255];

	if(aes_gcm_decrypt(ciphertext, ciphertext_len, NULL, 0, mac, key, nonce, newPlaintext)) {
		puts("integrity good");
	}


	fwrite(newPlaintext, plaintext_len, 1, stdout);
	puts("");	

	struct pointerFile *ptr = createPtrFile("./pointer");

	printf("curfile%d\n", ptr->currentFile);
	printf("offset%lu\n", ptr->byteOffset);

	unsigned char k2[16];

	doGCMDecrypt(ptr, k2);
	puts("k2");
	fwrite(k2, 16, 1, stdout);
	puts("");

	ptr->currentFile ++;

	doGCMEncrypt(ptr, k2);

	return 0;
}