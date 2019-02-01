#include <stdio.h>
#include <string.h>

#include <check.h>

START_TEST(test_numbers)
{
    ck_assert_int_eq(2, 3);
}
END_TEST

// define test suite and cases
Suite *test_suite(void)
{
    Suite *s = suite_create("skycoin_crypto");
    TCase *tc;

    tc = tcase_create("checksums");
    tcase_add_test(tc, test_numbers);
    suite_add_tcase(s, tc);

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
