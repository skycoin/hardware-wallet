/*
 * This file is part of the SKYCOIN project, https://www.skycoin.net/
 *
 * Copyright (C) 2018 <contact@skycoin.net>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __RIPEMD160_H__
#define __RIPEMD160_H__

#include <stdint.h>

#define RIPEMD160_BLOCK_LENGTH   64
#define RIPEMD160_DIGEST_LENGTH  20

typedef struct _RIPEMD160_CTX {
    uint32_t total[2];    /*!< number of bytes processed  */
    uint32_t state[5];    /*!< intermediate digest state  */
    uint8_t buffer[RIPEMD160_BLOCK_LENGTH];   /*!< data block being processed */
} RIPEMD160_CTX;

void ripemd160_Init(RIPEMD160_CTX *ctx);
void ripemd160_Update(RIPEMD160_CTX *ctx, const uint8_t *input, uint32_t ilen);
void ripemd160_Final(RIPEMD160_CTX *ctx, uint8_t output[RIPEMD160_DIGEST_LENGTH]);
void ripemd160(const uint8_t *msg, uint32_t msg_len, uint8_t hash[RIPEMD160_DIGEST_LENGTH]);

#endif
