/*
 * This file is part of the Skycoin project, https://www.skycoin.net/
 *
 * Copyright (C) 2018 Skycoin Project <contact@skycoin.net>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.	If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include "swtimer.h"
#include "timer.h"

/* Software stopwatch timers */
#define MAX_TIMERS 16

typedef struct {
	bool active;
	// Zero-delay for ascending counters, else countdown
	uint32_t delay;
	// Ticks at last time timer was either started or reset
	uint32_t checkpoint;
} TIMER;

TIMER sw_timers[MAX_TIMERS];

/*
 * Initialise stopwatch timers
 */
void timer_init_sw(void) {
	for (int i = 0; i < MAX_TIMERS; ++i) {
		sw_timers[i].active = false;
		sw_timers[i].checkpoint = 0;
	}
}

SWTIMER stopwatch_start(uint32_t timeout) {
	for (int i = 0; i < MAX_TIMERS; ++i) {
		if (sw_timers[i].active)
			continue;
		sw_timers[i].active = true;
		sw_timers[i].delay = timeout;
		sw_timers[i].checkpoint = timer_ms();
		return (SWTIMER) i;
	}
	return INVALID_TIMER;
}

uint32_t stopwatch_counter(SWTIMER timerId) {
	if (timerId >= MAX_TIMERS) {
		return INFINITE_TS;
	}
	TIMER* t = sw_timers + timerId;
	if (!t->active) {
		return INFINITE_TS;
	}
	// FIXME: Conditional statement needed ?
	uint32_t counter = (t->checkpoint > timer_ms())? t->checkpoint - timer_ms() : UINT32_MAX - t->checkpoint + timer_ms();
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

void stopwatch_reset(SWTIMER timerId) {
	if (timerId < MAX_TIMERS) {
		sw_timers[timerId].checkpoint = timer_ms();
	}
}

void stopwatch_close(SWTIMER timer) {
	if (timer < MAX_TIMERS) {
		sw_timers[timer].active = false;
		sw_timers[timer].checkpoint = 0;
	}
}

