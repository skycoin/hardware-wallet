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

#ifndef __TIMERIMPL_H__
#define __TIMERIMPL_H__

#include <stdint.h>
#include <stdbool.h>

/* Software stopwatch timers */
#define MAX_TIMERS 16

typedef struct {
	bool active;
	// Zero-delay for ascending counters, else countdown
	uint32_t delay;
	// Ticks at last time timer was either started or reset
	uint32_t checkpoint;
} TIMER;

void stopwatch_start_impl(TIMER* t, uint32_t timeout, uint32_t ticks);
uint32_t stopwatch_counter_impl(TIMER*, uint32_t ticks);
void stopwatch_reset_impl(TIMER*, uint32_t ticks);
void stopwatch_close_impl(TIMER*);

#endif
