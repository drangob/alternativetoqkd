#include <stdio.h>
#include <string.h>

#include "scrypt/libscrypt.h"

int main(int argc, char const *argv[]) {
	char password[] = "password";
	int passwordlength = strlen(password);

	FILE *fd = fopen("salt", "r");
	char salt[16];

	fread(salt, 1, 16, fd);
	fclose(fd);
	fd = fopen("salt", "w");
	fwrite(salt, 16, 1, fd);
	fclose(fd);

	int saltlength = 16;//strlen(salt);

	char output[32];


	libscrypt_scrypt(password, passwordlength, salt, saltlength, SCRYPT_N, SCRYPT_r, SCRYPT_p, output, 32);


	printf("password: %s\n", password);
	//printf("salt: %s\n\n", salt);
	printf("salt\n");
	fwrite(salt, 16, 1, stdout);
	printf("\noutput\n");
	fwrite(output, 32, 1, stdout);
	//printf("output: %s\n", output);
	printf("\n");


	return 0;
}
