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
#include "test_fsm.h"

// define test suite and cases
Suite *test_suite(void)
{
	Suite *s = suite_create("firmware");

	suite_add_tcase(s, add_fsm_tests(tcase_create("fsm")));
	suite_add_tcase(s, add_droplet_tests(tcase_create("droplet")));
	return s;
}

// run suite
int main(void)
{
	int number_failed;
	Suite *s = test_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	if (number_failed == 0) {
		printf("PASSED ALL TESTS\n");
	}
	return number_failed;
}
