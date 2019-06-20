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

#ifndef SKYCOIN_CRYPTO_H
#define SKYCOIN_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct TransactionOutput {
    uint64_t coin;
    uint64_t hour;
    uint8_t address[20];
} TransactionOutput;

typedef struct Transaction {
    uint8_t nbIn;
    uint8_t nbOut;
    uint8_t inAddress[8][32];
    TransactionOutput outAddress[8];
    int has_innerHash;
    uint8_t innerHash[32];
} Transaction;

void transaction_initZeroTransaction(Transaction* self);
void transaction_addInput(Transaction* self, uint8_t* address);
void transaction_addOutput(Transaction* self, uint32_t coin, uint32_t hour, char* address);
void transaction_innerHash(Transaction* self);
void transaction_msgToSign(Transaction* self, uint8_t index, uint8_t* signature);

void ecdh(const uint8_t* pub_key, const uint8_t* sec_key, uint8_t* ecdh_key);
void secp256k1sum(const uint8_t* seed, const size_t seed_length, uint8_t* digest);
void sha256sum(const uint8_t* seed, uint8_t* digest, size_t seed_length);
void add_sha256(const uint8_t* msg1, size_t msg1_len, const uint8_t* msg2, size_t msg2_len, uint8_t* out_digest);
void deterministic_key_pair_iterator(const uint8_t* seed, const size_t seed_length, uint8_t* nextSeed, uint8_t* seckey, uint8_t* pubkey);
void deterministic_key_pair_iterator_step(const uint8_t* seed, const size_t seed_length, uint8_t* seckey, uint8_t* pubkey);
void skycoin_pubkey_from_seckey(const uint8_t* seckey, uint8_t* pubkey);
void skycoin_address_from_pubkey(const uint8_t* pubkey, char* address, size_t* size_address);
int skycoin_ecdsa_sign_digest(const uint8_t* priv_key, const uint8_t* digest, uint8_t* sig);
void tohex(char* str, const uint8_t* buffer, int buffer_length);
void tobuff(const char* str, uint8_t* buf, size_t buffer_length);
void writebuf_fromhexstr(const char* str, uint8_t* buf);

 * @brief verify_pub_key ec secp256k1
 * @param pub_key pub key to b verified
 * @return true if the verification success
 */
bool verify_pub_key(const uint8_t* pub_key);

#endif
