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
#include "serialno.h"

// FIXME: Missing reference. Defined in libopencm3
void desig_get_unique_id(uint32_t *uuid)
{
	uint8_t *p = (uint8_t*) uuid;
	uint8_t i;
	for (i = 1; i <= 12; ++i, ++p) {
		*p = i;
	}
}

#define TEST_SERIALNO "DC5E1023685C298CA8E27611"

START_TEST(test_serialno_from_uuid)
{
	uint8_t uuid[32] = {
	       	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	       	0x09, 0x0a, 0x0b, 0x0c, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
       	};
	char serialno[SERIAL_NUMBER_SIZE * 2 + 1];
	serialno_from_uuid((uint32_t *) &uuid, serialno);
	ck_assert_str_eq(serialno, TEST_SERIALNO);
}
END_TEST

START_TEST(test_fill_serialno_fixed)
{
	char serialno[SERIAL_NUMBER_SIZE * 2 + 1];
	fill_serialno_fixed(serialno);
	ck_assert_str_eq(serialno, TEST_SERIALNO);
}
END_TEST

TCase *add_serialno_tests(TCase *tc) {
	tcase_add_test(tc, test_serialno_from_uuid);
	tcase_add_test(tc, test_fill_serialno_fixed);
	return tc;
}

