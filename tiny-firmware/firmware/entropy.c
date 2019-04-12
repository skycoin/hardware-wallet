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

#include "entropy.h"

#include <string.h>

#include "protob/c/messages.pb.h"
#include "vendor/skycoin-crypto/tools/sha2.h"
#include "rng.h"
#include "firmware/swtimer.h"
#include "timer.h"
#include "firmware/storage.h"
#include "skycoin_crypto.h"
#include "messages.h"
#include "messages.pb.h"

#define EXTERNAL_ENTROPY_TIMEOUT 60000
#define ENTROPY_RANDOMSALT_SIZE 256

static SWTIMER entropy_timeout = INVALID_TIMER;

ErrCode_t is_external_entropy_needed(void) {
	// Request for external entropy after 60000 clock ticks ellapsed
	if (stopwatch_counter(entropy_timeout)) {
		return ErrEntropyNotNeeded;
	}
	return ErrEntropyRequired;
}

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

static uint8_t entropy_mixer_prev_val[SHA256_DIGEST_LENGTH] = {0};

void reset_entropy_mix_256(void) {
	if (entropy_timeout == INVALID_TIMER) {
		entropy_timeout = stopwatch_start(EXTERNAL_ENTROPY_TIMEOUT);
	}
	// FIXME : Read STM32_UUID instead
	entropy_mix_256((uint8_t*)storage_uuid_str, sizeof(storage_uuid_str), NULL);
	uint8_t rndbuf[ENTROPY_RANDOMSALT_SIZE];
	random_buffer(rndbuf, sizeof(rndbuf));
	entropy_mix_256(rndbuf, sizeof(rndbuf), NULL);
	entropy_salt_mix_256(NULL, 0, NULL);
}

void entropy_salt_mix_256(uint8_t *in, size_t in_len, uint8_t *buf) {
	if (entropy_timeout == INVALID_TIMER) {
		return;
	}
	#ifdef EMULATOR
		uint64_t salt_ticker = 0;
		random_buffer((uint8_t*)&salt_ticker, sizeof (salt_ticker));
	#else
		uint64_t salt_ticker = timer_ms();
	#endif	// EMULATOR
	// Salt source : System clock timer
	entropy_mix_256((uint8_t*)&salt_ticker, sizeof(salt_ticker), NULL);
	// Salt source : TRNG 32 bits
	uint32_t salt_trng = random32();
	random_buffer((uint8_t*)&salt_trng, sizeof (salt_trng));
	entropy_mix_256((uint8_t*)&salt_trng, sizeof(salt_trng), NULL);
	if (in != NULL) {
		entropy_mix_256(in, in_len, buf);
	}
}

void entropy_mix_256(const uint8_t *in, size_t in_len, uint8_t *out_mixed_entropy) {
	uint8_t val1[SHA256_DIGEST_LENGTH] = {0};
	compute_sha256sum(in, val1, in_len);
	uint8_t val2[SHA256_DIGEST_LENGTH] = {0};
	add_sha256(
		val1, sizeof (val1),
		entropy_mixer_prev_val, sizeof (entropy_mixer_prev_val),
		val2);
	uint8_t val3[SHA256_DIGEST_LENGTH] = {0};
	add_sha256(val1, sizeof (val1), val2, sizeof (val2), val3);
	memset(val1, 0, sizeof(val1));
	memcpy(entropy_mixer_prev_val, val3, sizeof(entropy_mixer_prev_val));
	memset(val3, 0, sizeof(val1));
	if (out_mixed_entropy != NULL) {
		memcpy(out_mixed_entropy, val2, SHA256_DIGEST_LENGTH);
	}
	memset(val2, 0, sizeof(val1));
}

void entropy_mix_n(const uint8_t *in, size_t in_len, uint8_t *out_mixed_entropy) {
	uint8_t* iptr = (uint8_t *) in;
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

void __attribute__((weak)) random_salted_buffer(uint8_t *buf, size_t len) {
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

extern uint8_t int_entropy[32];

void set_external_entropy(uint8_t *entropy, size_t len) {
	stopwatch_reset(entropy_timeout);
	entropy_salt_mix_256(entropy, len, int_entropy);
}

void check_entropy(void) {
#ifndef EMULATOR
	GET_MSG_POINTER(EntropyRequest, entropy_request);
	if (is_external_entropy_needed() == ErrEntropyRequired) {
		memset(&resp, 0, sizeof(EntropyRequest));
		msg_write(MessageType_MessageType_EntropyRequest, entropy_request);
		stopwatch_reset(entropy_timeout);
	}
#endif
}
