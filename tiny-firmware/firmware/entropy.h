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

#include "firmware/error.h"

#ifndef __TINYFIRMWARE_FIRMWARE_ENTROPY__
#define __TINYFIRMWARE_FIRMWARE_ENTROPY__

ErrCode_t verify_entropy(const uint8_t* const bytes, uint16_t size);

#endif  // __TINYFIRMWARE_FIRMWARE_ENTROPY__
