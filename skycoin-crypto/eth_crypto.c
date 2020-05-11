#include "skycoin_crypto.h"

#include <string.h>

#include "eth_constants.h"
#include "skycoin_signature.h"
#include "tools/secp256k1.h"
#include "tools/curves.h"
#include "tools/sha3.h"

int eth_address_from_pubkey(const uint8_t *pubkey, char *address, size_t *address_size) {
    const curve_info *curve = get_curve_by_name(SECP256K1_NAME);

    if (!pubkey_is_valid(curve->params, pubkey)) {
        return 0;
    }

    uint8_t pubkey_hash[SHA3_256_DIGEST_LENGTH] = {0};
    sha3_256(pubkey + 1, ETH_PUBKEY_LEN, pubkey_hash);

    memmove(address, pubkey_hash + 12, ETH_ADDR_LEN);
    *address_size = ETH_ADDR_LEN;

    return 0;
}
