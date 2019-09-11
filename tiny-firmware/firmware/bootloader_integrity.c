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
#include "string.h"

int check_bootloader(void) {
    uint8_t hash[32];
    memory_bootloader_hash(hash);
    return !memcmp(hash,
                   "\x35\xf7\xb6\x20\x72\xcc\x84\x6e\x63\x5a\x0b\x36\xd6\x60\x40\x50\x0e\x71\x6a\x7c\xad\x1e\x64\x50\x5f\xbd\x64\x21\xcf\x07\x75\x5e",
                   32);
}

