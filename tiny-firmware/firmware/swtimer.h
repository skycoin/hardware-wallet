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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __SWTIMER_H__
#define __SWTIMER_H__

#include <stdint.h>

#define INVALID_TIMER 0x7F
#define NO_TIMEOUT    0
#define INFINITE_TS   UINT32_MAX

typedef uint8_t SWTIMER;

void timer_init_sw(void);
SWTIMER stopwatch_start(uint32_t timeout);
uint32_t stopwatch_counter(SWTIMER);
void stopwatch_reset(SWTIMER);
void stopwatch_close(SWTIMER);

#endif
