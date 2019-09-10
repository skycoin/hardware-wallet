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

#include <stddef.h>

#include "error.h"

#ifndef __TINYFIRMWARE_FIRMWARE_ENTROPY__
#define __TINYFIRMWARE_FIRMWARE_ENTROPY__

#include "skycoin-crypto/tools/entropypool.h"

#define EXTERNAL_ENTROPY_MAX_SIZE 128

/**
 * @brief reset_entropy_mix_256 initialize the internal entropy pool with fixed and variable salts
 * @sa entropy_mix_256
 */
void reset_entropy_mix_256(void);

/**
 * @brief entropy_salt_mix_256 mixes variable salt sources within entropy pool value
 * @sa entropy_mix_256
 */
void entropy_salt_mix_256(uint8_t* in, size_t in_len, uint8_t* buf);

/**
 * @brief set_external_entropy This should be used from a EntropyAck only.
 * @param entropy the external entropy to be stored
 */
void set_external_entropy(uint8_t* entropy, size_t len);

/**
 * @brief is_external_entropy_needed determine whether current entropy 
 * @return Err_EntropyRequired if external entropy is needed
 * @return Err_EntropyNotNeeded if external entropy is not needed
 * @return Err_EntropyAvailable if external entropy is ready to be merged
 */
ErrCode_t is_external_entropy_needed(void);

/**
 * @brief request external entropy from peer if entropy timer timed out
 */
void check_entropy(void);

#endif // __TINYFIRMWARE_FIRMWARE_ENTROPY__
