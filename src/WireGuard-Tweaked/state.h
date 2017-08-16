/*
 * state.h
 *
 *  Created on: 16 Aug 2017
 *      Author: dan
 */

#ifndef STATE_H_
#define STATE_H_

#include "messages.h"

void state_message_create(struct state_data *packet, __le32 receiver_index, __le32 fileNum, __le64 byteOffset);

#endif /* STATE_H_ */
