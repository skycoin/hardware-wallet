/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#ifndef __RESET_H__
#define __RESET_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tiny-firmware/firmware/error.h"
#include "types.pb.h"

void reset_init(bool display_random, uint32_t _strength, bool passphrase_protection, bool pin_protection, const char* language, const char* label, bool skip_backup);
ErrCode_t reset_entropy(void);

/**
 * @brief reset_backup create a device bckup
 * @param separated true if called as a separate workflow via BackupMessage.
 * @return Ok if success.
 */
ErrCode_t reset_backup(bool separated);
uint32_t reset_get_int_entropy(uint8_t* entropy);
const char* reset_get_word(void);

// Functions exported or testing purposes
void reset_init_ex(bool display_random, uint32_t _strength, bool passphrase_protection, bool pin_protection, const char* language, const char* label, bool _skip_backup, const char* (*funcRequestPin)(PinMatrixRequestType mt, const char*msg));

#endif
