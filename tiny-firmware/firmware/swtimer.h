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

#ifndef __SWTIMER_H__
#define __SWTIMER_H__

#include <stdint.h>

#define INVALID_TIMER 0x7F
#define NO_TIMEOUT 0
#define INFINITE_TS UINT32_MAX

typedef uint8_t SWTIMER;

void timer_init_sw(void);
SWTIMER stopwatch_start(uint32_t timeout);
uint32_t stopwatch_counter(SWTIMER);
void stopwatch_reset(SWTIMER);
void stopwatch_close(SWTIMER);

#endif
