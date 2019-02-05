/*
 * This file is part of the SKYCOIN project, https://www.skycoin.net/
 *
 * Copyright (C) 2018 <contact@skycoin.net>
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


#ifndef SKYCOIN_CHECK_SIGNATURE_H
#define SKYCOIN_CHECK_SIGNATURE_H

#include <stdint.h>

int recover_pubkey_from_signed_message(const char* message, const uint8_t* signature, uint8_t* pubkey);

#endif