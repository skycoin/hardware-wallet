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

#include "check_digest.h"

#include <stdbool.h>
#include <string.h>

static bool matchhexdigit(char c)
{
    return ((c >= '0') && (c <= '9')) || ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F'));
}

// is_sha256_hash_hex returns true if the digest array looks like a
// hex-encoded sha256 hash
int is_sha256_hash_hex(char* digest)
{
    if (strlen(digest) != 64) {
        return false;
    }
    bool bDigest = true;
    for (int i = 0; i < 64 && bDigest; ++i) {
        bDigest &= matchhexdigit(digest[i]);
    }
    return bDigest;
}
