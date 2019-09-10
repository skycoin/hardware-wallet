/*
 * This file is part of the Skycoin project, https://skycoin.net/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 * Copyright (C) 2018-2019 Skycoin Project
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>
#include <string.h>

#include "skycoin-crypto/tools/sha2.h"
#include "tiny-firmware/bootloader/signatures.h"
#include "tiny-firmware/bootloader/bootloader.h"
#include "skycoin-crypto/skycoin_constants.h"
#include "skycoin-crypto/skycoin_signature.h"

#define PUBKEYS 5

#if SIGNATURE_PROTECT
#include "pub_keys.h"
#endif

#if SIGNATURE_DEBUG
static void displaySignatureDebug(const uint8_t* hash, const uint8_t* signature, const uint8_t* pubk, const uint8_t* stored_pubkey)
{
    uint8_t buf[32];
    memset(buf, 0, 32);

    layout32bits(hash, "Hash");

    layout32bits(signature, "Signature[0-31]");
    layout32bits(signature + 32, "Signature[32-63]");
    buf[0] = signature[64];
    layout32bits(buf, "Signature[64]");

    layout32bits(pubk, "Computed Pub[0-31]");
    buf[0] = pubk[32];
    layout32bits(buf, "Computed Pub[32]");

    layout32bits(stored_pubkey, "Pubkey[0-31]");
    buf[0] = stored_pubkey[32];
    layout32bits(buf, "Pubkey[32]");
}
#endif

int signatures_ok(uint8_t* store_hash)
{
    if (!firmware_present()) return SIG_FAIL; // no firmware present

    const uint32_t codelen = *((const uint32_t*)FLASH_META_CODELEN);

    uint8_t hash[32];
    sha256_Raw((const uint8_t*)FLASH_APP_START, codelen, hash);
    if (store_hash) {
        memcpy(store_hash, hash, 32);
    }

#if SIGNATURE_PROTECT

    const uint8_t sigindex1 = *((const uint8_t*)FLASH_META_SIGINDEX1);
    const uint8_t sigindex2 = *((const uint8_t*)FLASH_META_SIGINDEX2);
    const uint8_t sigindex3 = *((const uint8_t*)FLASH_META_SIGINDEX3);

    if (sigindex1 < 1 || sigindex1 > PUBKEYS) return SIG_FAIL; // invalid index
    if (sigindex2 < 1 || sigindex2 > PUBKEYS) return SIG_FAIL; // invalid index
    if (sigindex3 < 1 || sigindex3 > PUBKEYS) return SIG_FAIL; // invalid index

    if (sigindex1 == sigindex2) return SIG_FAIL; // duplicate use
    if (sigindex1 == sigindex3) return SIG_FAIL; // duplicate use
    if (sigindex2 == sigindex3) return SIG_FAIL; // duplicate use

    uint8_t pubkey1[SKYCOIN_PUBKEY_LEN];
    uint8_t pubkey2[SKYCOIN_PUBKEY_LEN];
    uint8_t pubkey3[SKYCOIN_PUBKEY_LEN];

    uint8_t sign1[SKYCOIN_SIG_LEN];
    uint8_t sign2[SKYCOIN_SIG_LEN];
    uint8_t sign3[SKYCOIN_SIG_LEN];

    memcpy(sign1, (const uint8_t*)FLASH_META_SIG1, SKYCOIN_SIG_LEN);
    if (0 != skycoin_ecdsa_verify_digest_recover(sign1, hash, pubkey1)) {
#if SIGNATURE_DEBUG
        displaySignatureDebug(hash, sign1, pubkey1, pubkey[sigindex1 - 1]);
#endif
        return SIG_FAIL;
    }
    if (0 != memcmp(pubkey1, pubkey[sigindex1 - 1], SKYCOIN_PUBKEY_LEN)) // failure
    {
#if SIGNATURE_DEBUG
        displaySignatureDebug(hash, sign1, pubkey1, pubkey[sigindex1 - 1]);
#endif
        return SIG_FAIL;
    }

    memcpy(sign2, (const uint8_t*)FLASH_META_SIG2, SKYCOIN_SIG_LEN);
    if (0 != skycoin_ecdsa_verify_digest_recover(sign2, hash, pubkey2)) {
#if SIGNATURE_DEBUG
        displaySignatureDebug(hash, sign2, pubkey2, pubkey[sigindex2 - 1]);
#endif
        return SIG_FAIL;
    }
    if (0 != memcmp(pubkey2, pubkey[sigindex2 - 1], SKYCOIN_PUBKEY_LEN)) // failure
    {
#if SIGNATURE_DEBUG
        displaySignatureDebug(hash, sign2, pubkey2, pubkey[sigindex2 - 1]);
#endif
        return SIG_FAIL;
    }

    memcpy(sign3, (const uint8_t*)FLASH_META_SIG3, SKYCOIN_SIG_LEN);
    if (0 != skycoin_ecdsa_verify_digest_recover(sign3, hash, pubkey3)) {
#if SIGNATURE_DEBUG
        displaySignatureDebug(hash, sign3, pubkey3, pubkey[sigindex3 - 1]);
#endif
        return SIG_FAIL;
    }
    if (0 != memcmp(pubkey3, pubkey[sigindex3 - 1], SKYCOIN_PUBKEY_LEN)) // failure
    {
#if SIGNATURE_DEBUG
        displaySignatureDebug(hash, sign3, pubkey3, pubkey[sigindex3 - 1]);
#endif
        return SIG_FAIL;
    }
#endif

    return SIG_OK;
}
