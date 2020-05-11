#ifndef HW_ETHEREUM_CRYPTO_H
#define HW_ETHEREUM_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

int eth_address_from_pubkey(const uint8_t *pubkey, char *address, size_t *address_size);

#endif //HW_ETHEREUM_CRYPTO_H
