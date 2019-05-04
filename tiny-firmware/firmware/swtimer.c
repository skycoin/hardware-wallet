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

#include "swtimer.h"
#include "timer.h"
#include "timerimpl.h"

TIMER sw_timers[MAX_TIMERS];

/************************************
 * Internal functions
 ************************************/

void stopwatch_start_impl(TIMER* t, uint32_t timeout, uint32_t ticks)
{
    t->active = true;
    t->delay = timeout;
    t->checkpoint = ticks;
}

uint32_t stopwatch_counter_impl(TIMER* t, uint32_t ticks)
{
    if (!t->active) {
        return INFINITE_TS;
    }
    // FIXME: Conditional statement needed ?
    uint32_t counter = (ticks > t->checkpoint) ? ticks - t->checkpoint : UINT32_MAX - ticks + t->checkpoint;
    if (!t->delay) {
        // Ascending counter
        return counter;
    }
    if (counter < t->delay) {
        // Countdown timer returns ticks left to get to zero
        return t->delay - counter;
    }
    // Countdown timer reached deadline
    return 0;
}

void stopwatch_reset_impl(TIMER* t, uint32_t ticks)
{
    t->checkpoint = ticks;
}

void stopwatch_close_impl(TIMER* t)
{
    t->active = false;
    t->checkpoint = 0;
    t->delay = 0;
}

/************************************
 * Public API functions
 ************************************/

/*
 * Initialise stopwatch timers
 */
void timer_init_sw(void)
{
    for (int i = 0; i < MAX_TIMERS; ++i) {
        // FIXME: swtimer_close_impl ?
        sw_timers[i].active = false;
        sw_timers[i].checkpoint = 0;
        sw_timers[i].delay = 0;
    }
}

SWTIMER stopwatch_start(uint32_t timeout)
{
    for (int i = 0; i < MAX_TIMERS; ++i) {
        if (sw_timers[i].active)
            continue;
        stopwatch_start_impl(sw_timers + i, timeout, timer_ms());
        return (SWTIMER)i;
    }
    return INVALID_TIMER;
}

uint32_t stopwatch_counter(SWTIMER timerId)
{
    if (timerId >= MAX_TIMERS) {
        return INFINITE_TS;
    }
    return stopwatch_counter_impl(sw_timers + timerId, timer_ms());
}

void stopwatch_reset(SWTIMER timerId)
{
    if (timerId < MAX_TIMERS) {
        stopwatch_reset_impl(sw_timers + timerId, timer_ms());
    }
}

void stopwatch_close(SWTIMER timer)
{
    if (timer < MAX_TIMERS) {
        stopwatch_close_impl(sw_timers + timer);
    }
}
