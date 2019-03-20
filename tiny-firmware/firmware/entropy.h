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

#endif  // __TINYFIRMWARE_FIRMWARE_ENTROPY__
