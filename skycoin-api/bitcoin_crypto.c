#include "skycoin_crypto.h"

#include <stdio.h> //sprintf
#include <string.h>

#include "skycoin_constants.h"
#include "skycoin_signature.h"
#include "tools/base58.h"
#include "tools/secp256k1.h"
#include "tools/curves.h"
#include "tools/ecdsa.h"
#include "tools/ripemd160.h"
#include "tools/sha2.h"

int bitcoin_address_from_pubkey(const uint8_t* pubkey, char* b58address, size_t* size_b58address){
    const curve_info* curve = get_curve_by_name(SECP256K1_NAME);

    if (!pubkey_is_valid(curve->params, pubkey)) {
        return 0;
    }

    uint8_t address[RIPEMD160_DIGEST_LENGTH + 1 + BITCOIN_ADDRESS_CHECKSUM_LENGTH] = {0};
    uint8_t r1[SHA256_DIGEST_LENGTH] = {0};
    uint8_t r2[SHA256_DIGEST_LENGTH] = {0};

    sha256sum(pubkey, r1, BITCOIN_PUBKEY_LEN);
    ripemd160(r1, SHA256_DIGEST_LENGTH, address);

    uint8_t digest[SHA256_DIGEST_LENGTH] = {0};
    memmove(address+1, address, RIPEMD160_DIGEST_LENGTH + BITCOIN_ADDRESS_CHECKSUM_LENGTH);
    address[0] = 0; // version byte

    sha256sum(address, digest, RIPEMD160_DIGEST_LENGTH + 1);
    sha256sum(digest, r2, sizeof(digest));
    memcpy(&address[RIPEMD160_DIGEST_LENGTH + 1], r2, BITCOIN_ADDRESS_CHECKSUM_LENGTH);

    if (b58enc(b58address, size_b58address, address, sizeof(address))) {
        return 1;
    }
    return 0;
}
