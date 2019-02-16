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

#include "test_droplet.h"
#include "droplet.h"
#include "skyparams.h"

START_TEST(test_droplet_all_digits)
{
  char msg[20];
  ck_assert_str_eq("99999999.999999", sprint_coins(99999999999999, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
  ck_assert_str_eq("10000000.000001", sprint_coins(10000000000001, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
  ck_assert_str_eq("2.000001", sprint_coins(2000001, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
}
END_TEST

START_TEST(test_droplet_small_buffer)
{
  char msg[20];
/*  ck_assert_ptr_null(sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 3, msg));
  ck_assert_ptr_null(sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 4, msg));
  ck_assert_ptr_null(sprint_coins(coins, SKYPARAM_DROPLET_PRECISION_EXP, 5, msg)); */
  ck_assert_str_eq("0.0001", sprint_coins(100, SKYPARAM_DROPLET_PRECISION_EXP, 6, msg));
}
END_TEST

START_TEST(test_droplet_trim_fraction)
{
  char msg[20];
  ck_assert_str_eq("2.01", sprint_coins(2010000, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
}
END_TEST

START_TEST(test_droplet_trim_integer)
{
  char msg[20];
  ck_assert_str_eq("2", sprint_coins(2000000, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
  ck_assert_str_eq("1", sprint_coins(1000000, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
  ck_assert_str_eq("0", sprint_coins(0, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
  ck_assert_str_eq("2001300", sprint_coins(2001300000000, SKYPARAM_DROPLET_PRECISION_EXP, 20, msg));
}
END_TEST

TCase *add_droplet_tests(TCase *tc) {
  tcase_add_test(tc, test_droplet_all_digits);
  tcase_add_test(tc, test_droplet_small_buffer);
  tcase_add_test(tc, test_droplet_trim_fraction);
  tcase_add_test(tc, test_droplet_trim_integer);
  return tc;
}

