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

#include "skycoin_check_signature.h"

#include "curves.h"
#include "secp256k1.h"
#include "ecdsa.h"
#include <string.h> // memcpy
// #include "bignum.h"

/*
Compute uncompressed public key from compact signature.

sig: 65 bytes compact recoverable signature
digest: 32 bytes sha256 digest
pubkey: 33 bytes compress pubkey

Returns 0 on failure, 1 on success

Success means that the signature is valid and that a valid public key was
recovered from the signed message.
The caller must compare the recovered pubkey to the expected pubkey.
*/
int recover_pubkey_from_signed_digest(const uint8_t* digest, const uint8_t* sig, uint8_t* pubkey)
{
    /*
    SKYCOIN CIPHER AUDIT
	Compare to functions: RecoverPublicKey, Signature.Recover
    */
	const ecdsa_curve* curve = get_curve_by_name(SECP256K1_NAME)->params;

    bignum256 r, s, e;
    curve_point cp, cp2;

    // read r and s
    bn_read_be(sig, &r);
    bn_read_be(sig + 32, &s);
    if (!bn_is_less(&r, &curve->order) || bn_is_zero(&r)) {
        return 0;
    }
    if (!bn_is_less(&s, &curve->order) || bn_is_zero(&s)) {
        return 0;
    }
    uint8_t recid = sig[64];

    // cp = R = k * G (k is secret nonce when signing)
    if (recid & 2) {
        bn_add(&r, &curve->order);
        if (!bn_is_less(&r, &curve->prime)) {
            return 0;
        }
    }

    memcpy(&cp.x, &r, sizeof(bignum256));

    // compute y from x
    uncompress_coords(curve, recid & 1, &cp.x, &cp.y);
    if (!ecdsa_validate_pubkey(curve, &cp)) {
        return 0;
    }
    // r := r^-1
    bn_inverse(&r, &curve->order);

    // e = -digest
    bn_read_be(digest, &e);
    while (!(uint8_t)e.val[0]) {
        for (int i = 0; i < 8; ++i) {
            bn_rshift(&e);
        }
    }

    bn_multiply(&r, &e, &curve->order);
    bn_subtractmod(&curve->order, &e, &e, &curve->order);
    bn_fast_mod(&e, &curve->order);
    bn_mod(&e, &curve->order);

    bn_multiply(&r, &s, &curve->order);

    // cp := s * R = s * k *G
    point_multiply(curve, &s, &cp, &cp);
    // cp2 := -digest * G
    scalar_multiply(curve, &e, &cp2);

    // cp := (s * k - digest) * G = (r*priv) * G = r * Pub
    point_add(curve, &cp2, &cp);

    // write compressed pubkey
    if (bn_is_odd(&cp.y)) {
    	pubkey[0] = 0x03;
    } else {
    	pubkey[0] = 0x02;
    }
    bn_write_be(&cp.x, pubkey + 1);

    return 1;
}
