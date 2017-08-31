/*
 * state.c
 *
 *  Created on: 16 Aug 2017
 *      Author: Daniel Horbury
 */


#include "messages.h"
#include "state.h"

//little adapter to get the data and pass it back
int get_key_and_state(struct random_bits_key_state *keyStateStruct){
	extern int getKeyAndState(u8 *out, __le32 *fileNum, __le64 *byteOffset);
	return getKeyAndState(keyStateStruct->key, &keyStateStruct->fileNum, &keyStateStruct->byteOffset);
}

int get_key_from_state(struct random_bits_key_state *keyStateStruct){
	extern int getKeyFromState(u8 *out, __le32 *fileNum,  __le64 *byteOffset);
	return getKeyFromState(keyStateStruct->key, &keyStateStruct->fileNum, &keyStateStruct->byteOffset);
}

void pack_state(struct random_bits_key_state *keyStateStruct, u8 *buff) {
	memcpy(buff, &keyStateStruct->fileNum, sizeof(keyStateStruct->fileNum));
	memcpy(buff+sizeof(keyStateStruct->fileNum),&keyStateStruct->byteOffset, sizeof(keyStateStruct->byteOffset));
}

void unpack_state(struct random_bits_key_state *keyStateStruct, u8 *buff) {
	memcpy(&keyStateStruct->fileNum, buff, sizeof(keyStateStruct->fileNum));
	memcpy(&keyStateStruct->byteOffset, buff+sizeof(keyStateStruct->fileNum), sizeof(keyStateStruct->byteOffset));
}
