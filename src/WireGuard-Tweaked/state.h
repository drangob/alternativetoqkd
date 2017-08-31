/*
 * state.h
 *
 *  Created on: 16 Aug 2017
 *      Author: Daniel Horbury
 */

#ifndef STATE_H_
#define STATE_H_

#include "messages.h"

struct random_bits_key_state {
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	__le32 fileNum;
	__le64 byteOffset;
};

int get_key_and_state(struct random_bits_key_state *keyStateStruct);

int get_key_from_state(struct random_bits_key_state *keyStateStruct);

void pack_state(struct random_bits_key_state *keyStateStruct, u8 *buff);

void unpack_state(struct random_bits_key_state *keyStateStruct, u8 *buff);
#endif /* STATE_H_ */
