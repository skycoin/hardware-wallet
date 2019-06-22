/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (C) 2017 Saleem Rashid <trezor@saleemrashid.com>
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

#include <stdint.h>

#include "tiny-firmware/firmware/usb.h"

#include "tiny-firmware/firmware/messages.h"
#include "tiny-firmware/timer.h"

static volatile char tiny = 0;

void usbInit(void)
{
    emulatorSocketInit();
}

#if DEBUG_LINK
#define _ISDBG (((iface == 1) ? 'd' : 'n'))
#else
#define _ISDBG ('n')
#endif

extern bool simulateButtonPress;
extern int buttonPressType;

void usbPoll(void)
{
    emulatorPoll();

    static uint8_t buffer[64];

    int iface = 0, i, j = 0;

    if (emulatorSocketRead(&iface, buffer, sizeof(buffer)) > 0) {
#if EMULATOR
        for (i = 0; i < 5; i++) {
            if (buffer[i] == i) {
                j++;
            } else {
                break;
            }
        }
        if (j == 5) {
            simulateButtonPress = true;
            buttonPressType = buffer[5];
            return;
        } else {
            simulateButtonPress = false;
#endif
            if (!tiny) {
                msg_read_common(_ISDBG, buffer, sizeof(buffer));
            } else {
                msg_read_tiny(buffer, sizeof(buffer));
            }
#if EMULATOR
        }
#endif
    }

    const uint8_t* data = msg_out_data();
    if (data != NULL) {
        emulatorSocketWrite(0, data, 64);
    }
}

char usbTiny(char set)
{
    char old = tiny;
    tiny = set;
    return old;
}

void usbSleep(uint32_t millis)
{
    uint32_t start = timer_ms();

    while ((timer_ms() - start) < millis) {
        usbPoll();
    }
}
