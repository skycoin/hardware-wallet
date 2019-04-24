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

#include "pinmatrix.h"

#include "test_protect.h"

extern char pinmatrix_perm[10];

START_TEST(test_pinMatrixDoneOK)
{
	char pin_code[4] = {0};
	strcpy(pin_code, "953");
	translate_pin_code("483926571", pin_code);
	ck_assert_str_eq(pin_code, "123");

	strcpy(pin_code, "294");
	translate_pin_code("514386792", pin_code);
	ck_assert_str_eq(pin_code, "123");

	strcpy(pin_code, "672");
	translate_pin_code("638591247", pin_code);
	ck_assert_str_eq(pin_code, "123");
}
END_TEST

START_TEST(test_pinMatrixDoneWithWrongChars)
{
	char pin_code[4] = {0};
	strcpy(pin_code, "9A3");
	translate_pin_code("483926571", pin_code);
	ck_assert_str_eq(pin_code, "1");

	strcpy(pin_code, "9BC");
	translate_pin_code("483926571", pin_code);
	ck_assert_str_eq(pin_code, "1");

	strcpy(pin_code, "95D");
	translate_pin_code("483926571", pin_code);
	ck_assert_str_eq(pin_code, "12");

	strcpy(pin_code, "B5D");
	translate_pin_code("483926571", pin_code);
	ck_assert_str_eq(pin_code, "");
}
END_TEST

TCase *add_protect_tests(TCase *tc){
	tcase_add_test(tc, test_pinMatrixDoneOK);
	tcase_add_test(tc, test_pinMatrixDoneWithWrongChars);
	return tc;
}
