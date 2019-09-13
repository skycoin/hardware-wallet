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

#include "tiny-firmware/firmware/protect.h"

extern char* TEST_PIN1;
extern char* TEST_PIN2;

const char* pin_reader_ok(PinMatrixRequestType pinReqType, const char* text);

const char* pin_reader_alt(PinMatrixRequestType pinReqType, const char* text);

const char* pin_reader_wrong(PinMatrixRequestType pinReqType, const char* text);

