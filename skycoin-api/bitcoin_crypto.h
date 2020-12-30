#ifndef BITCOIN_CRYPTO_H
#define BITCOIN_CRYPTO_H

#include "tools/sha2.h"
#include "tools/hasher.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "skycoin_crypto.h"

int bitcoin_address_from_pubkey(const uint8_t* pubkey, char* b58address, size_t* size_b58address);

int bitcoin_ecdsa_sign_digest(const uint8_t* priv_key, const uint8_t* digest, uint8_t* sig);

int compile_script(uint8_t* pubkeyhash, uint8_t* script);

#endif
