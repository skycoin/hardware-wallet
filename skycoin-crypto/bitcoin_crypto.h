#ifndef BITCOIN_CRYPTO_H
#define BITCOIN_CRYPTO_H

#include "tools/sha2.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

int bitcoin_address_from_pubkey(const uint8_t* pubkey, char* b58address, size_t* size_b58address);

#endif
