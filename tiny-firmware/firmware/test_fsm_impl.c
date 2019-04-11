//
// Created by Skycoin.
//

#include "test_fsm_impl.h"
#include <check.h>


START_TEST(sample1)
{

}
END_TEST


START_TEST(sample2)
{

}
END_TEST


START_TEST(sample3)
{

}
END_TEST


START_TEST(sample4)
{

}
END_TEST


START_TEST(sample5)
{

}
END_TEST


START_TEST(sample6)
{

}
END_TEST


START_TEST(sample7)
{

}
END_TEST


START_TEST(sample8)
{

}
END_TEST


START_TEST(sample9)
{

}
END_TEST


START_TEST(sample10)
{

}
END_TEST

TCase* add_timer_tests(TCase *tc) {
    tcase_add_test(tc, sample1);
    tcase_add_test(tc, sample2);
    tcase_add_test(tc, sample3);
    tcase_add_test(tc, sample4);
    tcase_add_test(tc, sample5);
    tcase_add_test(tc, sample6);
    tcase_add_test(tc, sample7);
    tcase_add_test(tc, sample8);
    tcase_add_test(tc, sample9);
    tcase_add_test(tc, sample10);
    return tc;
}
