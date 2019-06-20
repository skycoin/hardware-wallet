/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2019 Skycoin Project
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "skycoin_signature.h"

#include <string.h>

#include "skycoin_constants.h"
#include "secp256k1.h"
#include "curves.h"
#include "ecdsa.h"

// sig 65 bytes compact recoverable signature
// digest 32 bytes sha256 hash
// pub_key 33 bytes compressed pubkey
// Returns 0 on success, 1 on failure
// Caller must check that the recovered public key matches the signature's claimed owner
int skycoin_ecdsa_verify_digest_recover(const uint8_t* sig, const uint8_t* digest, uint8_t* pub_key)
{
	uint8_t long_pub_key[65];
	curve_point point;
	const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

	int ret = ecdsa_verify_digest_recover(curve->params, long_pub_key, sig, digest, sig[64]);

	// validate pubkey
 	if (!ecdsa_read_pubkey(curve->params, long_pub_key, &point)) {
 		return 1;
 	}

 	compress_pubkey(long_pub_key, pub_key);

	return ret;
}

void compress_pubkey(const uint8_t* long_pub_key, uint8_t* pub_key) {
	memcpy(pub_key + 1, long_pub_key + 1, 32);
	if (long_pub_key[64] & 1) {
		pub_key[0] = 0x03;
	} else {
		pub_key[0] = 0x02;
	}
}
