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


#ifndef SKYCOIN_CHECK_SIGNATURE_H
#define SKYCOIN_CHECK_SIGNATURE_H

#include <stdint.h>

int recover_pubkey_from_signed_message(const char* message, const uint8_t* signature, uint8_t* pubkey);

#endif
