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

#define "droplet.h"
#define "skyparams.h"

START_TEST(test_droplet_all_digits)
{
  char msg[20];
  uint64_t coins = 99999999999999;
  ck_assert_str_eq("99999999.999999", sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));

  coins = 10000000000001;
  ck_assert_str_eq("100000000.000001", sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
}
END_TEST

START_TEST(test_droplet_buffer_underflow)
{
  char msg[20];
  uint64_t coins = 100;
  ck_assert_ptr_null(sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 3, msg));
  ck_assert_ptr_null(sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 4, msg));
  ck_assert_ptr_null(sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 5, msg));
  ck_assert_str_eq("0.0001", sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 6, msg));
}
END_TEST

