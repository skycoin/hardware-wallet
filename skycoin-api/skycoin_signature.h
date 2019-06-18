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

#ifndef SKYCOIN_SIGNATURE_H
#define SKYCOIN_SIGNATURE_H

#include <stddef.h>
#include <stdint.h>

int skycoin_ecdsa_verify_digest_recover(const uint8_t* sig, const uint8_t* digest, uint8_t* pub_key);
void compress_pubkey(const uint8_t* long_pub_key, uint8_t* pub_key);

#endif
