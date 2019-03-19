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

#define INTERNAL_ENTROPY_SIZE SHA256_DIGEST_LENGTH

static uint8_t entropy_mixer_prev_val[SHA256_DIGEST_LENGTH] = {0};

/**
 * @brief sum_sha256 make a sha256 over buffer
 * @param buffer in data
 * @param buffer_len in data len
 * @param out_digest out sha256 data
 */
static void sum_sha256(
		const uint8_t *buffer, size_t buffer_len, uint8_t *out_digest) {
	SHA256_CTX ctx;
	sha256_Init(&ctx);
	sha256_Update(&ctx, buffer, buffer_len);
	sha256_Final(&ctx, out_digest);
}

/**
 * @brief two_buffers_sum_sha256 append msg2 to msg1 and make a sum_sha256
 * @param msg1 buffer content
 * @param msg1_len buffer conttn len
 * @param msg2 buffer content
 * @param msg2_len buffer content len
 * @param out_digest sum_sha256 of msg1 appened to mag2
 * @sa sum_sha256
 */
static void two_buffers_sum_sha256(
		const uint8_t *msg1,
		size_t msg1_len,
		const uint8_t *msg2,
		size_t msg2_len,
		uint8_t *out_digest) {
	size_t two_msgs_len = msg1_len + msg2_len;
	uint8_t two_msgs[two_msgs_len];
	memset(two_msgs, 0, two_msgs_len);
	memcpy(two_msgs, msg1, msg1_len);
	memcpy(two_msgs + msg1_len, msg2, msg2_len);
	sum_sha256(two_msgs, two_msgs_len, out_digest);
}

void reset_entropy_mix_256(uint8_t *device_uuid, size_t device_uuid_len) {
	uint8_t null_buff[SHA256_DIGEST_LENGTH] = {0};
	if (!memcmp(null_buff, entropy_mixer_prev_val, sizeof (null_buff))) {
		random_buffer(entropy_mixer_prev_val, sizeof (entropy_mixer_prev_val));
	}
	uint8_t val1[SHA256_DIGEST_LENGTH] = {0};
	sum_sha256(device_uuid, device_uuid_len, val1);
	uint8_t val2[SHA256_DIGEST_LENGTH] = {0};
	two_buffers_sum_sha256(
				val1,
				sizeof (val1),
				entropy_mixer_prev_val,
				sizeof (entropy_mixer_prev_val),
				val2);
	memcpy(entropy_mixer_prev_val, val2, sizeof (entropy_mixer_prev_val));
}

void entropy_mix_256(const uint8_t *in, size_t in_len, uint8_t *out_mixed_entropy) {
	uint8_t val1[SHA256_DIGEST_LENGTH] = {0};
	sum_sha256(in, in_len, val1);
	uint8_t val2[SHA256_DIGEST_LENGTH] = {0};
	two_buffers_sum_sha256(
				val1,
				sizeof (val1),
				entropy_mixer_prev_val,
				sizeof (entropy_mixer_prev_val),
				val2);
	uint8_t val3[SHA256_DIGEST_LENGTH] = {0};
	two_buffers_sum_sha256(
		val1, sizeof (val1), val2, sizeof (val2), val3);
	uint8_t val4[SHA256_DIGEST_LENGTH] = {0};
#ifdef EMULATOR
	uint64_t ticker = 0;
	random_buffer((uint8_t*)&ticker, sizeof (ticker));
#else
	uint64_t ticker = get_system_millis();
#endif  // EMULATOR
	two_buffers_sum_sha256(
		val3, sizeof (val3), (uint8_t*)&ticker, sizeof (ticker), val4);
	memcpy(entropy_mixer_prev_val, val4, sizeof (entropy_mixer_prev_val));
	memcpy(out_mixed_entropy, val3, SHA256_DIGEST_LENGTH);
}
