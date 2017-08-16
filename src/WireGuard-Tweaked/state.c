/*
 * state.c
 *
 *  Created on: 16 Aug 2017
 *      Author: dan
 */


#include "messages.h"
#include "state.h"

void state_message_create(struct state_data *packet, __le32 receiver_index, __le32 fileNum, __le64 byteOffset) {
	packet->header.type = MESSAGE_STATE;
	packet->receiver_index = receiver_index;
	packet->fileNum = fileNum;
	packet->byteOffset = byteOffset;
}
