#include <stdio.h>
#include <stdlib.h>

#include "Quantis.h"

int main(int argc, char const *argv[]) {
	int count = QuantisCount(QUANTIS_DEVICE_USB);
	int devno = 0;
	if(count){
		printf("We have quantis!\n");
		//get some metadata from the device
		char *serial = QuantisGetSerialNumber(QUANTIS_DEVICE_USB, devno);
		printf("Serial = %s\n", serial);
		int dataRate = QuantisGetModulesDataRate(QUANTIS_DEVICE_USB, devno);
		printf("Data rate = %d\n", dataRate);
		//try to read some data into a 256 bit buffer
		void *buffer = malloc(32);
		//not an error code, documentation is wrong
		int code;
		if (code = QuantisRead(QUANTIS_DEVICE_USB, devno, buffer, 32)) {
			printf("We read some data. Copying to STDOUT\n");
			fwrite(buffer, 32, 1, stdout);
			puts("");
			free(buffer);
			printf("code%i\n", code);
		} else {
			printf("Data read failed.\n");
		}
	} else {
		printf("We dont have quantis!\n");
	}

	return 0;
}