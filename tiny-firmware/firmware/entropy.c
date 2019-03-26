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

static uint8_t external_entropy[EXTERNAL_ENTROPY_MAX_SIZE] = {0};
static bool external_entropy_available = false;

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

static uint8_t entropy_mixer_prev_val[SHA256_DIGEST_LENGTH] = {0};

void reset_entropy_mix_256(void) {
	#ifdef EMULATOR
		uint64_t ticker = 0;
		random_buffer((uint8_t*)&ticker, sizeof (ticker));
	#else
		uint64_t ticker = get_system_millis();
	#endif  // EMULATOR
	entropy_mix_256((uint8_t*)&ticker, sizeof(ticker), buf);
	// FIXME : Read STM32_UUID instead
	entropy_mix_256((uint8_t*)storage_uuid_str, sizeof(storage_uuid_str), buf);
	uint8_t buf[SHA256_DIGEST_LENGTH] = {0};
	random_buffer(buf, sizeof(buf));
	entropy_mix_256(buf, sizeof(buf), buf);
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
	memcpy(out_mixed_entropy, val2, SHA256_DIGEST_LENGTH);
}

ErrCode_t get_external_entropy(uint8_t* buffer) {
	if (external_entropy_available) {
		external_entropy_available = false;
		memcpy(buffer, external_entropy, sizeof(external_entropy));
		return ErrOk;
	}
	return ErrEntropyRequired;
}

void set_external_entropy(uint8_t *entropy) {
	external_entropy_available = true;
	memcpy(external_entropy, entropy, sizeof(external_entropy));
}
