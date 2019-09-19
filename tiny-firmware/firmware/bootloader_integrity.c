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
#include "bootloader_integrity.h"
#include "memory.h"
#include "sha2.h"
#include "string.h"

static char *bootloader_hashes[] = {
        "\x35\xf7\xb6\x20\x72\xcc\x84\x6e\x63\x5a\x0b\x36\xd6\x60\x40\x50\x0e\x71\x6a\x7c\xad\x1e\x64\x50\x5f\xbd\x64\x21\xcf\x07\x75\x5e",
        "\x13\xa2\x8e\xc7\x4d\x3c\xca\x6a\xe8\xc5\xf7\x26\xb1\x59\xf7\x0b\x5b\x86\x33\x1c\x51\x57\x93\xe0\x5c\x82\xde\x60\xc2\x7b\xd0\x18"
};

bool check_bootloader(void) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    memory_bootloader_hash(hash);
    bool is_official = false;
    for (uint32_t i = 0; i < sizeof(bootloader_hashes) / sizeof(char *); i++) {
        is_official |= !memcmp(hash, bootloader_hashes[i], 32);
    }
    return is_official;
}
