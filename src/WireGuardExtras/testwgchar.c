#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define PSK_LEN 32

int main() {
	int ret, fd;
	char key[PSK_LEN];
	//open 
	fd = open("/dev/wgchar", O_RDWR);             

	printf("Type in a 32bit key to send to the kernel module:\n");
	scanf("%s", key);
	printf("Sending msg to device [%s].\n", key);

	ret = write(fd, key, strlen(key)); 
	if (ret < 0){
		perror("Failed to write the message to the device.");
		return errno;
	}


	printf("Reading from the device...\n");

	int isFull = 0;

	ret = read(fd, &isFull, sizeof(int));
	if (ret < 0) {
		perror("Failed to read the message from the device.");
		return errno;
	}
	
	printf("Is there a key in the device? %s\n", isFull ? "True!" : "False!");

	return 0;
}
