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

#include "skycoin_constants.h"
#include "skycoin_signature.h"
#include "base58.h"
#include "secp256k1.h"
#include "curves.h"
#include "ecdsa.h"
#include "ripemd160.h"
#include "sha2.h"

extern void bn_print(const bignum256* a);

bool verify_pub_key(const uint8_t* pub_key) {
    const curve_info *info = get_curve_by_name(SECP256K1_NAME);
    if (!info) {
        return false;
    }
    const ecdsa_curve* curve = info->params;
    curve_point point;
    int res = ecdsa_read_pubkey(curve, pub_key, &point);
    memset(&point, 0, sizeof(point));
    if (res) {
        return true;
    }
    return false;
}
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

void skycoin_pubkey_from_seckey(const uint8_t* seckey, uint8_t* pubkey)
{
    /*
    SKYCOIN CIPHER AUDIT
    Compare to function: secp256k1.SkycoinPubkeyFromSeckey
    */
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
    ecdsa_get_public_key33(curve->params, seckey, pubkey);
}

// returns 0 if valid
int seckey_is_valid(const ecdsa_curve* curve, const uint8_t* seckey)
{
    /*
    SKYCOIN CIPHER AUDIT
    Compare to function: SeckeyIsValid

    Note: In SeckeyIsValid, it checks that seckey is not a negative value.
    This isn't necessary here because seckey can never be valid; bignum256 is unsigned.
    */
    bignum256 z;

    bn_read_be(seckey, &z);

    // must not be zero
    if (bn_is_zero(&z)) {
        return -1;
    }

    // must be less than order of curve
    if (!bn_is_less(&z, &curve->order)) {
        return -2;
    }

    return 0;
}

/*
Internal use only.

Returns 0 on success
*/
int deterministic_key_pair_iterator_step(const uint8_t* digest, uint8_t* seckey, uint8_t* pubkey)
{
    /*
    SKYCOIN CIPHER AUDIT
    Compare to function: secp256k1.GenerateDeterministicKeyPair
    */

    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

    memcpy(seckey, digest, SHA256_DIGEST_LENGTH);
    while (1) {
        sha256sum(seckey, seckey, SHA256_DIGEST_LENGTH);
        if (0 != seckey_is_valid(curve->params, seckey)) {
            continue;
        }

        skycoin_pubkey_from_seckey(seckey, pubkey);
        if (!pubkey_is_valid(curve->params, pubkey)) {
            // TODO: if pubkey is invalid, FAIL/PANIC
            return -1;
        }

        break;
    }

    return 0;
}

/*
secret_key: 32 bytes
remote_public_key: SKYCOIN_PUBKEY_LEN bytes (compressed public key)
ecdh_key: SKYCOIN_PUBKEY_LEN bytes (compressed public key)

Returns a nonzero value if arguments are invalid.
Caller should verify that the ecdh_key is a valid pubkey.
*/
int ecdh(const uint8_t* pub_key, const uint8_t* sec_key, uint8_t* ecdh_key)
{
    uint8_t long_pub_key[65] = {0};
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
    int ret = ecdh_multiply(curve->params, sec_key, pub_key, long_pub_key);
    if (ret != 0) {
        return ret;
    }
    compress_pubkey(long_pub_key, ecdh_key);
    return 0;
}

/*
Returns 0 on success
*/
int secp256k1sum(const uint8_t* seed, const size_t seed_length, uint8_t* digest)
{
    /*
    SKYCOIN CIPHER AUDIT
    Compare to function: secp256k1.Secp256k1Hash
    */
    uint8_t seckey[SKYCOIN_SECKEY_LEN] = {0};                           // generateKey(sha256(seed))
    uint8_t dummy_seckey[SKYCOIN_SECKEY_LEN] = {0};
    uint8_t pubkey[SKYCOIN_PUBKEY_LEN] = {0};                           // generateKey(sha256(sha256(seed))
    uint8_t hash[SHA256_DIGEST_LENGTH] = {0};                           // sha256(seed)
    uint8_t hash2[SHA256_DIGEST_LENGTH] = {0};                          // sha256(sha256(seed))
    uint8_t ecdh_key[SKYCOIN_PUBKEY_LEN] = {0};                         // ecdh(pubkey, seckey)

    // hash = sha256(seed)
    sha256sum(seed, hash, seed_length);

    // seckey, _ = deterministic_key_pair_iterator_step(hash)
    if (0 != deterministic_key_pair_iterator_step(hash, seckey, pubkey)) {
        // TODO: abort() on failure
        return -1;
    }

    // _, pubkey = deterministic_key_pair_iterator_step(sha256(hash))
    // This value usually equals the seckey generated above, but not always (1^-128 probability)
    sha256sum(hash, hash2, sizeof(hash));
    if (0 != deterministic_key_pair_iterator_step(hash2, dummy_seckey, pubkey)) {
        // TODO: abort() on failure
        return -2;
    }

    // ecdh_key = ECDH(pubkey, seckey)
    // Note: we don't care if the ecdh_key is a valid public key, we're only
    // using the bytes to salt the hash
    if (0 != ecdh(pubkey, seckey, ecdh_key)) {
        // TODO: abort() on failure
        return -3;
    }

    // sha256(hash + ecdh_key)
    sha256sum_two(hash, SHA256_DIGEST_LENGTH, ecdh_key, SKYCOIN_PUBKEY_LEN, digest);

    return 0;
}

#define DEBUG_DETERMINISTIC_KEY_PAIR_ITERATOR 0

/*
next_seed should be 32 bytes (size of a secp256k1sum digest)

Returns 0 on success
*/
int deterministic_key_pair_iterator(const uint8_t* seed, const size_t seed_length, uint8_t* next_seed, uint8_t* seckey, uint8_t* pubkey)
{
    /*
    SKYCOIN CIPHER AUDIT
    Compare to function: secp254k1.DeterministicKeyPairIterator
    */
    uint8_t seed2[SHA256_DIGEST_LENGTH] = {0};

    if (0 != secp256k1sum(seed, seed_length, next_seed)) {
        return -1;
    }

    #if DEBUG_DETERMINISTIC_KEY_PAIR_ITERATOR
    char buf[256];
    tohex(buf, seed, seed_length);
    printf("seedIn: %s\n", buf);
    tohex(buf, next_seed, SHA256_DIGEST_LENGTH);
    printf("next_seed: %s\n", buf);
    #endif

    sha256sum_two(seed, seed_length, next_seed, SHA256_DIGEST_LENGTH, seed2);

    #if DEBUG_DETERMINISTIC_KEY_PAIR_ITERATOR
    tohex(buf, seed2, SHA256_DIGEST_LENGTH);
    printf("seed2: %s\n", buf);
    #endif

    if (0 != deterministic_key_pair_iterator_step(seed2, seckey, pubkey)) {
        return -1;
    }

    #if DEBUG_DETERMINISTIC_KEY_PAIR_ITERATOR
    tohex(buf, seckey, SKYCOIN_SECKEY_LEN);
    printf("seckey: %s\n", buf);
    tohex(buf, pubkey, SKYCOIN_PUBKEY_LEN);
    printf("pubkey: %s\n", buf);
    #endif

    return 0;
}

// priv_key 32 bytes private key
// digest 32 bytes sha256 hash
// sig 65 bytes compact recoverable signature
int skycoin_ecdsa_sign_digest(const uint8_t* priv_key, const uint8_t* digest, uint8_t* sig)
{
    int ret;
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);
    uint8_t recid = 0;
    ret = ecdsa_sign_digest(curve->params, priv_key, digest, sig, &recid, NULL);
    if (recid > 4) {
        // This should never happen; we can abort() here, as a sanity check
        return -3;
    }
    sig[64] = recid;
    return ret;
}

/**
 * @brief sha256sum hash over buffer
 * @param buffer in data
 * @param buffer_len in data len
 * @param out_digest out sha256 data
 */
void sha256sum(const uint8_t* data, uint8_t* out_digest /*size SHA256_DIGEST_LENGTH*/, size_t data_length)
{
    SHA256_CTX ctx;
    sha256_Init(&ctx);
    sha256_Update(&ctx, data, data_length);
    sha256_Final(&ctx, out_digest);
}

/**
 * @brief sha256sum_two compute sha256(msg1 + msg2)
 * @param msg1 buffer content
 * @param msg1_len buffer content len
 * @param msg2 buffer content
 * @param msg2_len buffer content len
 * @param out_digest sum_sha256 of msg1 appened to mag2
 */
void sha256sum_two(const uint8_t* msg1, size_t msg1_len, const uint8_t* msg2, size_t msg2_len, uint8_t* out_digest)
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

Returns 0 if the address cannot fit into the b58address array or if the pubkey is not valid
*/
int skycoin_address_from_pubkey(const uint8_t* pubkey, char* b58address, size_t* size_b58address)
{
    /*
    SKYCOIN CIPHER AUDIT
    https://github.com/skycoin/skycoin/wiki/Technical-background-of-version-0-Skycoin-addresses

    address = ripemd160(sha256(sha256(pubkey))
    checksum = sha256(address+version)
    */
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

    if (!pubkey_is_valid(curve->params, pubkey)) {
        return 0;
    }

    uint8_t address[RIPEMD160_DIGEST_LENGTH + 1 + 4] = {0};
    uint8_t r1[SHA256_DIGEST_LENGTH] = {0};
    uint8_t r2[SHA256_DIGEST_LENGTH] = {0};

    // ripemd160(sha256(sha256(pubkey))
    sha256sum(pubkey, r1, SKYCOIN_PUBKEY_LEN);
    sha256sum(r1, r2, sizeof(r1));
    ripemd160(r2, SHA256_DIGEST_LENGTH, address);

    // compute base58 address
    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    address[RIPEMD160_DIGEST_LENGTH] = 0; // version byte

    // checksum
    sha256sum(address, digest, RIPEMD160_DIGEST_LENGTH + 1);
    memcpy(&address[RIPEMD160_DIGEST_LENGTH + 1], digest, SKYCOIN_ADDRESS_CHECKSUM_LENGTH);

    if (b58enc(b58address, size_b58address, address, sizeof(address))) {
        return 1;
    }
    return 0;
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

BigTxContext* context;

BigTxContext* initBigTxContext() {
    context = malloc(sizeof(BigTxContext));
    return context;
}

BigTxContext* getBigTxCtx(){
    return context;
}

void printSHA256(BigTxContext* ctx) {
    uint8_t* buffer = (uint8_t*)ctx->sha256_ctx.buffer;
    for(uint8_t i = 0; i < 64; ++i)
        printf("%u ",buffer[i]);
    printf("\n");
}

void bigTxCtx_printInnerHash(BigTxContext* self) {
    for(uint8_t i = 0; i < 32; ++i) {
        printf("%u ", self->innerHash[i]);
    }
    printf("\n");
}

void bigTxCtx_AddHead(uint8_t count) {
    BigTxContext* ctx = getBigTxCtx();
    uint8_t data[4];
    memcpy(data, &count, 1);
    memset(&data[1], 0, 3);
    sha256_Update(&ctx->sha256_ctx, data, 4);
}

void bigTxCtx_UpdateInputs(BigTxContext* self, uint8_t inputs [7][32], uint8_t count) {
    for(uint8_t i = 0; i < count; ++i) {
        sha256_Update(&self->sha256_ctx,inputs[i], 32);
        self->current_nbIn +=1;
    }
}

void bigTxCtx_UpdateOutputs(BigTxContext* self, BigTxOutput outputs[7], uint8_t count){
    for (uint8_t i = 0; i < count; ++i) {
        uint8_t data[40];
        uint8_t bitcount = 0;
        data[bitcount] = 0;
        bitcount += 1;
        memcpy(&data[bitcount], outputs[i].address, 20);
        bitcount += 20;
        memcpy(&data[bitcount], (uint8_t*)&outputs[i].coin, 4);
        bitcount += 4;
        memset(&data[bitcount], 0, 4);
        bitcount += 4;
        memcpy(&data[bitcount], (uint8_t*)&outputs[i].hour, 4);
        bitcount += 4;
        memset(&data[bitcount], 0, 4);
        bitcount += 4;
        sha256_Update(&self->sha256_ctx, data, bitcount);
        self->current_nbOut+=1;
    }
}

void bigTxCtx_finishInnerHash(BigTxContext* self){
    sha256_Final(&self->sha256_ctx, self->innerHash);
    self->has_innerHash = true;
}

void bigTxCtx_Destroy(BigTxContext* ctx){
    free(ctx);
}