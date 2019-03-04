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

#include "error.h"

static uint8_t make_histogram(const uint8_t* const bytes, uint16_t bytes_size, uint8_t *hist);
static uint64_t entropy(const uint8_t *const hist, uint8_t histlen, uint16_t len);
ErrCode_t verify_entropy(const uint8_t* const bytes, uint16_t size);

