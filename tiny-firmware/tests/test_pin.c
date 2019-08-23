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

#include "test_pin.h"

char* TEST_PIN1 = "123";
char* TEST_PIN2 = "246";

const char* pin_reader_ok(PinMatrixRequestType pinReqType, const char* text)
{
    (void)text;
    (void)pinReqType;
    return TEST_PIN1;
}

const char* pin_reader_alt(PinMatrixRequestType pinReqType, const char* text)
{
    (void)text;
    (void)pinReqType;
    return TEST_PIN2;
}

const char* pin_reader_wrong(PinMatrixRequestType pinReqType, const char* text)
{
    (void)text;
    switch (pinReqType) {
    case PinMatrixRequestType_PinMatrixRequestType_NewFirst:
        return TEST_PIN1;
    case PinMatrixRequestType_PinMatrixRequestType_NewSecond:
        return "456";
    default:
        break;
    }
    return "789";
}

