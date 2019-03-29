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

#include "test_timer.h"
#include "timerimpl.h"
#include "swtimer.h"

// Defined in swtimer.c
extern TIMER sw_timers[MAX_TIMERS];

START_TEST(test_swtimer_inactive)
{
  TIMER *t = &sw_timers[0];
  t->active = false;
  ck_assert_uint_eq(stopwatch_counter(0), INFINITE_TS);
}
END_TEST

START_TEST(test_swtimer_counter_asc)
{
  TIMER *t = &sw_timers[0];
  t->delay = 0;

  // Start from scratch
  stopwatch_close_impl(t);
  // Start timer
  stopwatch_start_impl(t, 0, 12345000);
  // Counter after 678 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12345678), 678);
  // If timer had been reset
  stopwatch_reset_impl(t, 12345050);
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12345678), 628);
  // And after 20 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12345698), 648);
  // Close timer
  stopwatch_close_impl(t);
  // Restart timer at a later time
  stopwatch_start_impl(t, 0, 23456000);
  // Counter after 789 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23456789), 789);
  // If timer had been reset
  stopwatch_reset_impl(t, 23456050);
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23456789), 739);
  // And after 10 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23456799), 749);
  // Close timer
  stopwatch_close_impl(t);
}
END_TEST

START_TEST(test_swtimer_counter_desc)
{
  TIMER *t = &sw_timers[0];
  // Start from scratch
  stopwatch_close_impl(t);
  // Start timer
  stopwatch_start_impl(t, 1000, 12345000);
  // Counter after 678 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12345678), 322);
  // If timer had been reset
  stopwatch_reset_impl(t, 12345050);
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12345678), 372);
  // And after 20 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12345678), 392);
  // And after 999 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12346677), 1);
  // And after 1000 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12346678), 0);
  // And after 1001 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12346679), 0);
  // And after 1100 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 12346778), 0);
  // Close timer
  stopwatch_close_impl(t);
  // Restart timer at a later time
  stopwatch_start_impl(t, 0, 23456000);
  // Counter after 789 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23456789), 789);
  // If timer had been reset
  stopwatch_reset_impl(t, 23456050);
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23456789), 739);
  // And after 10 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23456799), 749);
  // And after 999 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23457788), 1);
  // And after 1000 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23457789), 0);
  // And after 1001 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23457790), 0);
  // And after 1100 ticks
  ck_assert_uint_eq(stopwatch_counter_impl(t, 23457889), 0);
  // Close timer
  stopwatch_close_impl(t);
}
END_TEST

/*
START_TEST(test_swtimer_asc_overflow)
{
  TIMER *t = &sw_timers[0];
}
END_TEST

START_TEST(test_swtimer_counter_overflow)
{
  TIMER *t = &sw_timers[0];
}
END_TEST

START_TEST(test_swtimer_full)
{
  TIMER *t = &sw_timers[0];
}
END_TEST
*/

TCase *add_timer_tests(TCase *tc) {
  tcase_add_test(tc, test_swtimer_inactive);
  tcase_add_test(tc, test_swtimer_counter_asc);
  tcase_add_test(tc, test_swtimer_counter_desc);
  /* tcase_add_test(tc, test_swtimer_asc_overflow);
  tcase_add_test(tc, test_swtimer_counter_overflow);
  tcase_add_test(tc, test_swtimer_full); */
  return tc;
}

