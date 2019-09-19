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

#include <check.h>
#include <stdbool.h>

TCase* add_fsm_tests(TCase* tc);

// Used in test_fsm_skycoin.c
void forceGenerateMnemonic(uint32_t wc);
bool is_base16_char(char c);