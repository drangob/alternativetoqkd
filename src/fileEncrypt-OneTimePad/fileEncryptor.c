#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <argp.h>


#include "bitConsumption.h"


static char doc[] = "One time pad file encryptor to be used with disks of random bits.";

//arguments accepted
static char args_doc[] = "INPUT-FILE OUTPUT-FILE RANDOM-PATH";

//Extra options
static struct argp_option options[] = {
	{"state-path", 's', "PATH", 0, "source of random bits"},
	{"fastfoward-file",  'f', "FileNUM", 0,  "file to fastfoward to"},
	{"fastfoward-offset",  'o', "OffsetNUM", 0,  "offset to fastfoward to"},
	{ 0 }
};

// Container for all of our arguments
struct arguments {
	char *args[3]; 
	uint32_t fastfoward_file ;
	uint64_t fastfoward_offset ;
	char *statePath ;
	int isState;
	int isFFFile;
	int isFFOffset;
};

int zeroArguments(struct arguments *args) {
	args->isState = 0;
	args->isFFFile = 0;
	args->isFFOffset = 0;
}
//Parse each argument, populating the struct
static error_t
parse_opt (int key, char *arg, struct argp_state *state) {
  /* Get the input argument from argp_parse, which we
	 know is a pointer to our arguments structure. */
	struct arguments *arguments = state->input;

	switch (key) {
		case 's':
			arguments->statePath = arg;
			arguments->isState = 1;
			break;
		case 'f':
			arguments->fastfoward_file = atoi(arg);
			arguments->isFFFile = 1;
			break;
		case 'o':
			arguments->fastfoward_offset = atoi(arg);
			arguments->isFFOffset = 1;
			break;

		case ARGP_KEY_ARG:
			if (state->arg_num >= 3)
			/* Too many arguments. */
				argp_usage (state);

			arguments->args[state->arg_num] = arg;

			break;

		case ARGP_KEY_END:
			if (state->arg_num < 3)
			/* Not enough arguments. */
				argp_usage (state);
			if(arguments->isFFOffset && !arguments->isFFFile || arguments->isFFFile && !arguments->isFFOffset)
				argp_usage (state);
			break;

		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };

int main(int argc, char *argv[]) {
	struct arguments arguments;
	zeroArguments(&arguments);

	argp_parse (&argp, argc, argv, 0, 0, &arguments);

	char *input = arguments.args[0];
	char *output = arguments.args[1];
	char *randomPath = arguments.args[2];

	char statePath[150];
	strcpy(statePath, arguments.args[2]); 

	if(arguments.isState){
		strcpy(statePath, arguments.statePath);
	}
	struct pointerFile *ptr = readPtrFile(statePath, "nextAvailable.ptr");

	//open up the input file to read the file
	FILE *fd = fopen(input, "r");
	if(fd == NULL) {
		perror("opening input failed");
		exit(-1);
	}

	//get file size
	fseek(fd, 0, SEEK_END);
	uint32_t fileSize = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	//read contents to memory
	unsigned char *fileContents = malloc(fileSize);
	fread(fileContents, fileSize, 1, fd);
	fclose(fd);

	//will be a malloced size of filesize
	unsigned char *randoms; 
	if(arguments.isFFOffset && arguments.isFFFile) {
		randoms = getBytesWithFastForward(randomPath, ptr, fileSize, arguments.fastfoward_file, arguments.fastfoward_offset);
		printf("Did crypto with file:%u and offset:%lu\n", arguments.fastfoward_file, arguments.fastfoward_offset);
	} else {
		printf("Doing crypto with file:%u and offset:%lu\n", ptr->currentFile, ptr->byteOffset);
		randoms = getBytes(randomPath, ptr, fileSize);	
	}
	
	if(randoms == NULL) {
		exit(-1);
	}

	scryptLogout(ptr);
	free(ptr);

	//do the crypto xor 
	for (int i = 0; i < fileSize; i++) {
		fileContents[i] = fileContents[i] ^ randoms[i];
	}	

	//write the output
	FILE *outputfd = fopen(output, "w");
	if(outputfd == NULL) {
		perror("opening input failed");
		exit(-1);
	}
	fwrite(fileContents, fileSize, 1, outputfd);
	fclose(outputfd);

	//cleanup
	free(fileContents);
	free(randoms);


	return 0;
}