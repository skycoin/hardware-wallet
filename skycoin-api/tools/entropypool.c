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

void entropy_mix_256(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy)
{
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
    memset(val3, 0, sizeof(val1));
    if (out_mixed_entropy != NULL) {
        memcpy(out_mixed_entropy, val2, SHA256_DIGEST_LENGTH);
    }
    memset(val2, 0, sizeof(val1));
}

void entropy_mix_n(const uint8_t* in, size_t in_len, uint8_t* out_mixed_entropy)
{
    uint8_t* iptr = (uint8_t*)in;
    uint8_t* optr;
    size_t i;
    for (i = in_len, optr = out_mixed_entropy;
         i >= SHA256_DIGEST_LENGTH;
         i -= SHA256_DIGEST_LENGTH, iptr += SHA256_DIGEST_LENGTH, optr += SHA256_DIGEST_LENGTH) {
        entropy_mix_256(iptr, SHA256_DIGEST_LENGTH, optr);
    }
    if (i > 0) {
        uint8_t tmp[SHA256_DIGEST_LENGTH] = {0};
        entropy_mix_256(iptr, i, tmp);
        memcpy(optr, &tmp, i);
        memset(&tmp, 0, sizeof(tmp));
    }
    iptr = optr = NULL;
}

void __attribute__((weak)) random_salted_buffer(uint8_t* buf, size_t len)
{
    random_buffer(buf, len);

    uint8_t tmp[SHA256_DIGEST_LENGTH] = {0};
    uint8_t *bptr, *tptr;
    size_t i, j;
    for (i = len, bptr = buf; i >= SHA256_DIGEST_LENGTH; i -= SHA256_DIGEST_LENGTH) {
        entropy_mix_256(bptr, SHA256_DIGEST_LENGTH, tmp);
        for (j = SHA256_DIGEST_LENGTH, tptr = tmp; j; --j, ++tptr, ++bptr) {
            // FIXME: XOR the whole architecture-specific word
            *bptr = *bptr ^ *tptr;
        }
    }
    if (i > 0) {
        entropy_mix_256(bptr, i, tmp);
        for (tptr = tmp; i; --i, ++tptr, ++bptr) {
            // FIXME: XOR the whole architecture-specific word
            *bptr = *bptr ^ *tptr;
        }
    }
    memset(&tmp, 0, sizeof(tmp));
    bptr = tptr = NULL;
}

uint32_t __attribute__((weak)) random32_salted(void)
{
    uint32_t retval;
    random_salted_buffer((uint8_t *) &retval, sizeof(uint32_t));
    return retval;
}

