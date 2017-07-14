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

	char output[250];
	char newoutput[250];


	libscrypt_scrypt(password, passwordlength, salt, saltlength, SCRYPT_N, SCRYPT_r, SCRYPT_p, output, 250);

	printf("password: %s\n", password);
	printf("salt: %s\n", salt);
	printf("output: %s\n", output);


	return 0;
}
