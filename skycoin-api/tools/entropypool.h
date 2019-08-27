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
#include <stdint.h>

#ifndef __SKYAPI_ENTROPYPOOL__
#define __SKYAPI_ENTROPYPOOL__

/**
 * @brief entropy_mix_256 32 bytes entropy pool mixer.
 * @param in buffer to be mixed in with entropy pool
 * @param out_mixed_entropy out parameter to store the 256bits mixed entropy value.
 */
void entropy_mix_256(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy);

/**
 * @brief entropy_mix_n entropy pool mixer of arbitrary size
 * @param in entropy with 256 bits. 
 * @param in_len number of bytes to process from input buffer and to store into output buffer
 * @param out_mixed_entropy points to a buffer of at least `len` bytes to store the mixed entropy
 */
void entropy_mix_n(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy);

/**
 * @brief random_salted_buffer entropy salted with internal pool state
 * @param buf buffer used to store random salted entropy
 * @param len number of random bytes to generate
 */
void random_salted_buffer(uint8_t* buf, size_t len);

/**
 * @brief random32_salted random 32 bit integer salted with values of entropy buffer
 */
uint32_t random32_salted(void);

/**
 * @brief backup_entropy_pool get snapshot of entropy pool buffer
 * @param buf buffer used to store entropy pool state (at least SHA256_DIGEST_LENGTH bytes)
 */
void backup_entropy_pool(uint8_t* buf);

#endif // __SKYAPI_ENTROPYPOOL__
