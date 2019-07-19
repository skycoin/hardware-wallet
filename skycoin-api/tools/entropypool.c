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

#include "entropypool.h"

#include <string.h>

#include "rand.h"
#include "sha2.h"
#include "skycoin_crypto.h"

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

// Accumulated entropy pool
static uint8_t entropy_mixer_prev_val[SHA256_DIGEST_LENGTH] = {0};

void backup_entropy_pool(uint8_t* buf){
  memcpy((void *) buf, (void *) entropy_mixer_prev_val, sizeof(entropy_mixer_prev_val));
}

void entropy_mix_256(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy)
{
    if (in == NULL) {
      return;
    }
    uint8_t val1[SHA256_DIGEST_LENGTH] = {0};
    sha256sum(in, val1, in_len);
    uint8_t val2[SHA256_DIGEST_LENGTH] = {0};
    sha256sum_two(
        val1, sizeof(val1),
        entropy_mixer_prev_val, sizeof(entropy_mixer_prev_val),
        val2);
    uint8_t val3[SHA256_DIGEST_LENGTH] = {0};
    sha256sum_two(val1, sizeof(val1), val2, sizeof(val2), val3);
    memset(val1, 0, sizeof(val1));
    memcpy(entropy_mixer_prev_val, val3, sizeof(entropy_mixer_prev_val));
    memset(val3, 0, sizeof(val3));
    if (out_mixed_entropy != NULL) {
        memcpy(out_mixed_entropy, val2, SHA256_DIGEST_LENGTH);
    }
    memset(val2, 0, sizeof(val2));
}

// Repeated invocation of `random32_salted` will be resolved from cache
static uint8_t random_buffer_cache[SHA256_DIGEST_LENGTH] = {0};
static uint8_t random_buffer_index = 0xff;

_Static_assert(sizeof(random_buffer_cache) % sizeof(uint32_t) == 0, "Alignment error random_buffer_cache");

void random_salted_buffer(uint8_t* buf, size_t len)
{
    // Invalidate random32() buffer cache
    random_buffer_index = 0xff;

    // Random bytes to be mixed with entropy pool have to fit in buckets of size SHA256_DIGEST_LENGTH
    // to prevent padding added by mixing function.

    uint8_t tmp[SHA256_DIGEST_LENGTH] = {0};
    uint8_t random_chunk[SHA256_DIGEST_LENGTH] = {0};
    uint8_t *bufptr = buf, *tmpptr = tmp, *rndptr = random_chunk;
    size_t i, j;

    for (i = len; i > 0; ) {
        _random_buffer(random_chunk, SHA256_DIGEST_LENGTH);
        entropy_mix_256(random_chunk, SHA256_DIGEST_LENGTH, tmp);
        for (tmpptr = tmp, rndptr = random_chunk, j = SHA256_DIGEST_LENGTH; i > 0 && j > 0; ++tmpptr, ++bufptr, ++rndptr, --i, --j) {
            *bufptr = *rndptr ^ *tmpptr;
        }
    }
    memset(&random_chunk, 0, sizeof(random_chunk));
    memset(&tmp, 0, sizeof(tmp));
    bufptr = tmpptr = rndptr = NULL;
}

uint32_t random32_salted(void)
{
    // On index overflow regenerate new random buffer
    if (random_buffer_index >= sizeof(random_buffer_cache)) {
        random_salted_buffer(random_buffer_cache, sizeof(random_buffer_cache));
        random_buffer_index = 0;
    }
    uint32_t retval = *(((uint32_t *) random_buffer_cache) + random_buffer_index);
    random_buffer_index += sizeof(uint32_t);
    return retval;
}

