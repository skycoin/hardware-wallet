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

#include <libopencm3/stm32/desig.h>

#include "tiny-firmware/firmware/skywallet.h"
#include "tiny-firmware/oled.h"
#include "tiny-firmware/gen/bitmaps.h"
#include "tiny-firmware/util.h"
#include "tiny-firmware/firmware/usb.h"
#include "tiny-firmware/setup.h"
#include "tiny-firmware/firmware/storage.h"
#include "tiny-firmware/layout.h"
#include "tiny-firmware/firmware/layout2.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/timer.h"
#include "tiny-firmware/buttons.h"
#include "tiny-firmware/firmware/gettext.h"
#include "tiny-firmware/firmware/fastflash.h"
#include "tiny-firmware/firmware/factory_test.h"
#include "tiny-firmware/firmware/entropy.h"
#include "tiny-firmware/memory.h"

extern uint32_t storage_uuid[STM32_UUID_LEN / sizeof(uint32_t)];
int main(void)
{
#if defined(EMULATOR) && EMULATOR == 1
    setup();
    __stack_chk_guard = random32(); // this supports compiler provided unpredictable stack protection checks
    oledInit();
#else  // defined(EMULATOR) && EMULATOR == 1
    setupApp();
    __stack_chk_guard = random32(); // this supports compiler provided unpredictable stack protection checks
#endif // defined(EMULATOR) && EMULATOR == 1

#if FASTFLASH
    uint16_t state = gpio_port_read(BTN_PORT);
    if ((state & BTN_PIN_NO) == 0) {
        run_bootloader();
    }
#endif

    timer_init();

#if !defined(EMULATOR) || EMULATOR == 0
    memory_rdp_level();
    desig_get_unique_id(storage_uuid);
    // enable MPU (Memory Protection Unit)
    mpu_config();
#else
    random_buffer((uint8_t*)storage_uuid, sizeof(storage_uuid));
#endif // !defined(EMULATOR) || EMULATOR == 0

#if DEBUG_LINK
    oledSetDebugLink(1);
    storage_wipe();
#endif

    oledDrawBitmap(0, 0, &bmp_skycoin_logo64);
    oledRefresh();

    storage_init();
    layoutHome();
    usbInit();
    for (;;) {
        usbPoll();
        check_lock_screen();
        check_factory_test();
        check_entropy();
    }

    return 0;
}
