/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "firmware/error.h"

#include <stddef.h>

#ifndef __TINYFIRMWARE_FIRMWARE_ENTROPY__
#define __TINYFIRMWARE_FIRMWARE_ENTROPY__

#define EXTERNAL_ENTROPY_MAX_SIZE 128

/**
 * @brief reset_entropy_mix_256 initialze the internal entropy pool
 * @sa entropy_mix_256
 */
void reset_entropy_mix_256(void);

/**
 * @brief entropy_mix_256 entropy pool mixer.
 * @param in entropy with 256 bits. 
 * @param in_len in len.
 * @param out_mixed_entropy out parama to store the mixed entropy with 256 bits.
 */
void entropy_mix_256(
		const uint8_t *in, size_t in_len, uint8_t *out_mixed_entropy);

/**
 * @brief get_external_entropy get a previous saved external entropy
 * @details This entropy have to be used only once.
 * @param buffer with the external entropy
 * @return An error code if there is not external entropy available
 * @sa set_external_entropy
 */
ErrCode_t get_external_entropy(uint8_t* buffer);

/**
 * @brief set_external_entropy This should be used from a EntropyAck only.
 * @param entropy the external entropy to be stored
 */
void set_external_entropy(uint8_t *entropy);

#endif  // __TINYFIRMWARE_FIRMWARE_ENTROPY__
