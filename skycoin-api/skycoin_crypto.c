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

#include "skycoin_crypto.h"

#include <stdio.h> //sprintf
#include <string.h>

#include "base58.h"
#include "secp256k1.h"
#include "curves.h"
#include "ecdsa.h"
#include "ripemd160.h"
#include "sha2.h"

extern void bn_print(const bignum256* a);

void tohex(char* str, const uint8_t* buffer, int buffer_length)
{
    int i;
    for (i = 0; i < buffer_length; ++i) {
        sprintf(&str[2 * i], "%02x", buffer[i]);
    }
}

void tobuff(const char* str, uint8_t* buf, size_t buffer_length)
{
    for (size_t i = 0; i < buffer_length; i++) {
        uint8_t c = 0;
        if (str[i * 2] >= '0' && str[i * 2] <= '9') c += (str[i * 2] - '0') << 4;
        if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F') c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;
        if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9') c += (str[i * 2 + 1] - '0');
        if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F') c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
        buf[i] = c;
    }
}

void writebuf_fromhexstr(const char* str, uint8_t* buf)
{
    size_t len = strlen(str) / 2;
    if (len > 32) len = 32;
    tobuff(str, buf, len);
}

void generate_pubkey_from_seckey(const uint8_t* seckey, uint8_t* pubkey)
{
	/*
	SKYCOIN CIPHER AUDIT
	Compare to function: secp256k1.PubkeyFromSeckey
	*/
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
    ecdsa_get_public_key33(curve->params, seckey, pubkey);
}

void generate_deterministic_key_pair(const uint8_t* seed, const size_t seed_length, uint8_t* seckey, uint8_t* pubkey)
{
	/*
	SKYCOIN CIPHER AUDIT
	Compare to function: secp256k1.GenerateDeterministicKeyPair
	Note: Does not conform to secp256k1.GenerateDeterministicKeyPair
		- Needs to check secret key for validity
		- Needs to have retry logic to brute force a valid secret and public key
	*/
    compute_sha256sum(seed, seckey, seed_length);
    generate_pubkey_from_seckey(seckey, pubkey);
}

/*
secret_key: 32 bytes
remote_public_key: SKYCOIN_PUBKEY_LEN bytes (compressed public key)
ecdh_key: SKYCOIN_PUBKEY_LEN bytes (compressed public key)
*/
void ecdh(const uint8_t* secret_key, const uint8_t* remote_public_key, uint8_t* ecdh_key)
{
    uint8_t mult[SKYCOIN_SIG_LEN] = {0};
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
    ecdh_multiply(curve->params, secret_key, remote_public_key, mult); // 65

    // Compress public key
    memcpy(&ecdh_key[1], &mult[1], SKYCOIN_PUBKEY_LEN-1);
    if (mult[64] % 2 == 0) {
        ecdh_key[0] = 0x02;
    } else {
        ecdh_key[0] = 0x03;
    }
}

/*
secret_key: 32 bytes
remote_public_key: SKYCOIN_PUBKEY_LEN bytes (compressed public key)
shared_secret: 32 bytes (sha256 hash)

Equivalent to:
sha256(ecdh(secret, public))
*/
void ecdh_shared_secret(const uint8_t* secret_key, const uint8_t* remote_public_key, uint8_t* shared_secret)
{
	/*
	SKYCOIN CIPHER AUDIT
	Compare to function: UNKNOWN
	Does this function have any purpose?
	*/
    uint8_t ecdh_key[SKYCOIN_PUBKEY_LEN] = {0};
    ecdh(secret_key, remote_public_key, ecdh_key);
    compute_sha256sum(ecdh_key, shared_secret, SKYCOIN_PUBKEY_LEN);
}

void secp256k1sum(const uint8_t* seed, const size_t seed_length, uint8_t* digest)
{
	/*
	SKYCOIN CIPHER AUDIT
	Compare to function: secp256k1.Secp256k1Hash
	*/
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};							// generateKey(sha256(seed))
    uint8_t dummy_seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};							// generateKey(sha256(sha256(seed))
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};							// sha256(seed)
    uint8_t hash2[SHA256_DIGEST_LENGTH] = {0};							// sha256(sha256(seed))
    uint8_t ecdh_key[SKYCOIN_PUBKEY_LEN] = {0};							// ecdh(pubkey, seckey)
    uint8_t hash_ecdh[SHA256_DIGEST_LENGTH + SKYCOIN_PUBKEY_LEN] = {0}; // sha256(sha256(seed)+ecdh)

    // hash = sha256(seed)
    compute_sha256sum(seed, hash, seed_length);

    // seckey = deriveSecKey(hash)
    // AUDIT: This should be deterministicKeyPairIteratorStep(), which performs sha256() in a loop,
    // each time checking that the resulting secret key is valid. This code is missing that.
    compute_sha256sum(hash, seckey, sizeof(hash));

    // pubkey = derivePubKey(sha256(hash))
    compute_sha256sum(hash, hash2, sizeof(hash));
    generate_deterministic_key_pair(hash2, SHA256_DIGEST_LENGTH, dummy_seckey, pubkey);

    // ecdh_key = ECDH(pubkey, seckey)
    ecdh(seckey, pubkey, ecdh_key);

    // sha256(hash + ecdh_key)
    memcpy(hash_ecdh, hash, sizeof(hash));
    memcpy(&hash_ecdh[SHA256_DIGEST_LENGTH], ecdh_key, sizeof(ecdh_key));
    compute_sha256sum(hash_ecdh, digest, sizeof(hash_ecdh));
}

// next_seed should be 32 bytes (size of a secp256k1sum digest)
void generate_deterministic_key_pair_iterator(const uint8_t* seed, const size_t seed_length, uint8_t* next_seed, uint8_t* seckey, uint8_t* pubkey)
{
	/*
	SKYCOIN CIPHER AUDIT
	Compare to function: secp254k1.DeterministicKeyPairIterator
	*/
    uint8_t seed1[SHA256_DIGEST_LENGTH] = {0};
    uint8_t seed2[SHA256_DIGEST_LENGTH] = {0};

    // AUDIT: Why 256 here? seed can be any length in the skycoin cipher code.
    // If there are length restrictions imposed here, they must be enforced with a check
    uint8_t keypair_seed[256] = {0};

    secp256k1sum(seed, seed_length, seed1);

    // AUDIT: buffer overflow if seed_length > 256 - SHA256_DIGEST_LENGTH
    memcpy(keypair_seed, seed, seed_length);
    memcpy(&keypair_seed[seed_length], seed1, SHA256_DIGEST_LENGTH);
    memcpy(next_seed, seed1, SHA256_DIGEST_LENGTH);

    compute_sha256sum(keypair_seed, seed2, seed_length + sizeof(seed1));
    generate_deterministic_key_pair(seed2, SHA256_DIGEST_LENGTH, seckey, pubkey);
}

/**
 * @brief compute_sha256sum hash over buffer
 * @param buffer in data
 * @param buffer_len in data len
 * @param out_digest out sha256 data
 */
void compute_sha256sum(const uint8_t* data, uint8_t* out_digest /*size SHA256_DIGEST_LENGTH*/, size_t data_length)
{
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data, data_length);
    sha256_Final(&ctx, out_digest);
}

/**
 * @brief add_sha256 make the sum of msg2 and to msg1
 * @param msg1 buffer content
 * @param msg1_len buffer conttn len
 * @param msg2 buffer content
 * @param msg2_len buffer content len
 * @param out_digest sum_sha256 of msg1 appened to mag2
 */
void add_sha256(const uint8_t* msg1, size_t msg1_len, const uint8_t* msg2, size_t msg2_len, uint8_t* out_digest)
{
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, msg1, msg1_len);
    sha256_Update(&ctx, msg2, msg2_len);
    sha256_Final(&ctx, out_digest);
}

/*
pubkey is the SKYCOIN_PUBKEY_LEN byte compressed pubkey

address_size is the size of the allocated address buffer, it will be overwritten by the computed address size
The address_size must be at least 36 bytes and the address buffer must be at least that large.
*/
void generate_skycoin_address_from_pubkey(const uint8_t* pubkey, char* b58address, size_t* size_b58address)
{
	/*
	SKYCOIN CIPHER AUDIT
	https://github.com/skycoin/skycoin/wiki/Technical-background-of-version-0-Skycoin-addresses

	address = ripemd160(sha256(sha256(pubkey))
	checksum = sha256(address+version)
	*/
    uint8_t address[RIPEMD160_DIGEST_LENGTH + 1 + 4] = {0};
    uint8_t r1[SHA256_DIGEST_LENGTH] = {0};
    uint8_t r2[SHA256_DIGEST_LENGTH] = {0};

    // ripemd160(sha256(sha256(pubkey))
    compute_sha256sum(pubkey, r1, SKYCOIN_PUBKEY_LEN);
    compute_sha256sum(r1, r2, sizeof(r1));
    ripemd160(r2, SHA256_DIGEST_LENGTH, address);

    // compute base58 address
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    address[RIPEMD160_DIGEST_LENGTH] = 0; // version byte

    // checksum
    compute_sha256sum(address, digest, RIPEMD160_DIGEST_LENGTH + 1);
    memcpy(&address[RIPEMD160_DIGEST_LENGTH + 1], digest, SKYCOIN_ADDRESS_CHECKSUM_LENGTH);

    b58enc(b58address, size_b58address, address, sizeof(address));
}

// uses secp256k1 curve
// priv_key is a 32 byte big endian stored number
// sig is 65 bytes (compact signature)
// digest is 32 bytes (sha256 hash)
int ecdsa_skycoin_sign(const uint32_t nonce_value, const uint8_t* priv_key, const uint8_t* digest, uint8_t* sig)
{
	/*
	SKYCOIN CIPHER AUDIT
	Compare to functions: secp256k1.Sign, Signature.Sign

	It appears that this function as written is adapted from ecdsa_sign_digest
	*/
    int i;
    curve_point R;
    bignum256 nonce, z, randk;
    bignum256* s = &R.y;
    uint8_t recid; // signature recovery byte

    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

    bn_read_be(digest, &z);

    for (i = 0; i < 1000; i++) {
        // generate random number nonce
        // generate_k_random(&nonce, &curve->params->order);

        // r = nonce*G
        bn_read_uint32(nonce_value, &nonce);
        scalar_multiply(curve->params, &nonce, &R);

        recid = R.y.val[0] & 1;

        // r = (rx mod n)
        if (!bn_is_less(&R.x, &curve->params->order)) {
            bn_subtract(&R.x, &curve->params->order, &R.x);
            recid |= 2;
        }
        // if r is zero, we retry
        if (bn_is_zero(&R.x)) {
            continue;
        }

        bn_inverse(&nonce, &curve->params->order);     // (nonce*rand)^-1
        bn_read_be(priv_key, s);                       // priv
        bn_multiply(&R.x, s, &curve->params->order);   // R.x*priv
        bn_add(s, &z);                                 // R.x*priv + z
        bn_multiply(&nonce, s, &curve->params->order); // (nonce*rand)^-1 (R.x*priv + z)
        bn_mod(s, &curve->params->order);

        // if s is zero, we retry
        if (bn_is_zero(s)) {
            continue;
        }

        // if S > order/2 => S = -S
        if (bn_is_less(&curve->params->order_half, s)) {
            bn_subtract(&curve->params->order, s, s);
            recid ^= 1;
        }
        // we are done, R.x and s is the result signature
        bn_write_be(&R.x, sig);
        bn_write_be(s, sig + 32);

        sig[64] = recid;

        memset(&nonce, 0, sizeof(nonce));
        memset(&randk, 0, sizeof(randk));

        return 0;
    }

    // Too many retries without a valid signature
    // -> fail with an error
    memset(&nonce, 0, sizeof(nonce));
    memset(&randk, 0, sizeof(randk));

    return -1;
}

void transaction_initZeroTransaction(Transaction* self)
{
    self->nbIn = 0;
    self->nbOut = 0;
    self->has_innerHash = 0;
}

void transaction_addInput(Transaction* self, uint8_t* address)
{
    memcpy(&self->inAddress[self->nbIn], address, 32);
    self->nbIn++;
};

void transaction_addOutput(Transaction* self, uint32_t coin, uint32_t hour, char* address)
{
    self->outAddress[self->nbOut].coin = coin;
    self->outAddress[self->nbOut].hour = hour;
    size_t len = 36;
    uint8_t b58string[36];
    b58tobin(b58string, &len, address);
    memcpy(self->outAddress[self->nbOut].address, &b58string[36 - len], len);
    self->nbOut++;
}

void transaction_innerHash(Transaction* self)
{
    uint8_t ctx[sizeof(Transaction)];
    memset(ctx, 0, sizeof(Transaction));
    uint64_t bitcount = 0;
    // serialized in
    uint8_t nbIn = self->nbIn;
    memcpy(&ctx[bitcount], &nbIn, 1);
    memset(&ctx[bitcount + 1], 0, 3);
    bitcount += 4;
    for (uint8_t i = 0; i < self->nbIn; ++i) {
        memcpy(&ctx[bitcount], (uint8_t*)&self->inAddress[i], 32);
        bitcount += 32;
    }

    // serialized out
    uint8_t nbOut = self->nbOut;
    memcpy(&ctx[bitcount], &nbOut, 1);
    memset(&ctx[bitcount + 1], 0, 3);
    bitcount += 4;
    for (uint8_t i = 0; i < self->nbOut; ++i) {
        ctx[bitcount] = 0;
        bitcount += 1;
        memcpy(&ctx[bitcount], &self->outAddress[i].address, 20);
        bitcount += 20;
        memcpy(&ctx[bitcount], (uint8_t*)&self->outAddress[i].coin, 4);
        bitcount += 4;
        memset(&ctx[bitcount], 0, 4);
        bitcount += 4;
        memcpy(&ctx[bitcount], (uint8_t*)&self->outAddress[i].hour, 4);
        bitcount += 4;
        memset(&ctx[bitcount], 0, 4);
        bitcount += 4;
    }

    SHA256_CTX sha256ctx;
    sha256_Init(&sha256ctx);
    sha256_Update(&sha256ctx, ctx, bitcount);
    sha256_Final(&sha256ctx, self->innerHash);
    self->has_innerHash = 1;
}

void transaction_msgToSign(Transaction* self, uint8_t index, uint8_t* msg_digest)
{
    if (index >= self->nbIn) {
        return;
    }
    // concat innerHash and transaction hash
    uint8_t shaInput[64];
    if (!self->has_innerHash) {
        transaction_innerHash(self);
    }
    memcpy(shaInput, self->innerHash, 32);
    memcpy(&shaInput[32], (uint8_t*)&self->inAddress[index], 32);
#ifdef EMULATOR
#if EMULATOR
    char str[128];
    tohex(str, shaInput, 64);
    printf("InnerHash computation on %s\n", str);
#endif
#endif
    // compute hash
    SHA256_CTX sha256ctx;
    sha256_Init(&sha256ctx);
    sha256_Update(&sha256ctx, shaInput, 64);
    sha256_Final(&sha256ctx, msg_digest);
}
