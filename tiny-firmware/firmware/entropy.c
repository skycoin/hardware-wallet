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
#include "timer.h"
#include "firmware/storage.h"
#include "skycoin_crypto.h"

#define EXTERNAL_ENTROPY_TIMEOUT 60000
#define ENTROPY_RANDOMSALT_SIZE 256

static uint8_t external_entropy[EXTERNAL_ENTROPY_MAX_SIZE] = {0};
static bool external_entropy_available = false;
static SWTIMER entropy_timeout = INVALID_TIMER;

ErrCode_t is_external_entropy_needed(void) {
	if (external_entropy_available) {
		return ErrEntropyAvailable;
	}
	// Request for external entropy after 60000 clock ticks ellapsed
	if (stopwatch_counter(entropy_timeout) > EXTERNAL_ENTROPY_TIMEOUT) {
		return ErrEntropyRequired;
	}
	return ErrEntropyNotNeeded;
}

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

static uint8_t entropy_mixer_prev_val[SHA256_DIGEST_LENGTH] = {0};

void reset_entropy_mix_256(void) {
	if (entropy_timeout == INVALID_TIMER) {
		entropy_timeout = stopwatch_open();
	}
	uint8_t buf[SHA256_DIGEST_LENGTH] = {0};
	// FIXME : Read STM32_UUID instead
	entropy_mix_256((uint8_t*)storage_uuid_str, sizeof(storage_uuid_str), buf);
	entropy_salt_mix_256(NULL, 0, buf);
}

void entropy_salt_mix_256(uint8_t *in, size_t in_len, uint8_t *buf) {
	if (entropy_timeout == INVALID_TIMER) {
		return;
	}
	if ((in != NULL) && (in_len > 0)) {
		entropy_mix_256(in, in_len, buf);
	}
	#ifdef EMULATOR
		uint64_t ticker = 0;
		random_buffer((uint8_t*)&ticker, sizeof (ticker));
	#else
		uint64_t ticker = get_system_millis();
	#endif	// EMULATOR
	entropy_mix_256((uint8_t*)&ticker, sizeof(ticker), buf);
	uint8_t rndbuf[ENTROPY_RANDOMSALT_SIZE];
	random_buffer(rndbuf, sizeof(rndbuf));
	entropy_mix_256(rndbuf, sizeof(rndbuf), buf);
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
	add_sha256(
		val1, sizeof (val1), val2, sizeof (val2), val3);
	memcpy(entropy_mixer_prev_val, val3, sizeof(entropy_mixer_prev_val));
	if (out_mixed_entropy != NULL) {
		memcpy(out_mixed_entropy, val2, SHA256_DIGEST_LENGTH);
	}
}

ErrCode_t get_external_entropy(uint8_t* buffer) {
	ErrCode_t action_needed = is_external_entropy_needed();
	if (action_needed == ErrEntropyAvailable) {
		external_entropy_available = false;
		memcpy(buffer, external_entropy, sizeof(external_entropy));
	}
	return action_needed;
}

void set_external_entropy(uint8_t *entropy) {
	external_entropy_available = true;
	stopwatch_reset(entropy_timeout);
	memcpy(external_entropy, entropy, sizeof(external_entropy));
}
