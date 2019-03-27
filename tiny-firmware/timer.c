/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2016 Saleem Rashid <trezor@saleemrashid.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "timer.h"

#include <libopencm3/stm32/rcc.h>
#include <libopencm3/cm3/systick.h>
#include <libopencm3/cm3/vector.h>

#include "rng.h"

/* 1 tick = 1 ms */
volatile uint64_t system_millis;

uint64_t get_system_millis(void) {
	return system_millis;
}

/* Software stopwatch timers */
#define MAX_TIMERS 16

typedef struct {
	bool active;
	uint64_t checkpoint;
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

SWTIMER stopwatch_open(void) {
	for (int i = 0; i < MAX_TIMERS; ++i) {
		if (sw_timers[i].active)
			continue;
		sw_timers[i].active = true;
		sw_timers[i].checkpoint = system_millis;
		return (SWTIMER) i;
	}
	return INVALID_TIMER;
}

int64_t stopwatch_counter(SWTIMER timerId) {
	if (timerId >= MAX_TIMERS) {
		return -1;
	}
	TIMER* t = sw_timers + timerId;
	if (!t->active) {
		return -1;
	}
	if (t->checkpoint > system_millis) {
		return t->checkpoint - system_millis;
	}
	return UINT64_MAX - t->checkpoint + system_millis;
}

void stopwatch_reset(SWTIMER timerId) {
	if (timerId < MAX_TIMERS) {
		sw_timers[timerId].checkpoint = system_millis;
	}
}

void stopwatch_close(SWTIMER timer) {
	if (timer < MAX_TIMERS) {
		sw_timers[timer].active = false;
		sw_timers[timer].checkpoint = 0;
	}
}

/*
 * Initialise the Cortex-M3 SysTick timer
 */
void timer_init(void) {
	random_buffer((uint8_t*)&system_millis, sizeof (system_millis));

	/*
	 * MCU clock (120 MHz) as source
	 *
	 *		 (120 MHz / 8) = 15 clock pulses
	 *
	 */
	systick_set_clocksource(STK_CSR_CLKSOURCE_AHB_DIV8);
	STK_CVR = 0;

	/*
	 * 1 tick = 1 ms @ 120 MHz
	 *
	 *		 (15 clock pulses * 1000 ms) = 15000 clock pulses
	 *
	 * Send an interrupt every (N - 1) clock pulses
	 */
	systick_set_reload(14999);

	/* SysTick as interrupt */
	systick_interrupt_enable();
	systick_counter_enable();

	timer_init_sw();
}

void sys_tick_handler(void) {
	system_millis++;
}
