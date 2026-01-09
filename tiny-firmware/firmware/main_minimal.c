/*
 * Minimal USB test firmware
 * This firmware only initializes USB and responds to GetFeatures
 * OLED blinks to show the firmware is running
 */

#include <libopencm3/stm32/desig.h>
#include <libopencm3/stm32/gpio.h>

#include "tiny-firmware/oled.h"
#include "tiny-firmware/gen/bitmaps.h"
#include "tiny-firmware/util.h"
#include "tiny-firmware/usb.h"
#include "tiny-firmware/setup.h"
#include "tiny-firmware/rng.h"
#include "tiny-firmware/timer.h"

extern uint32_t storage_uuid[12 / sizeof(uint32_t)];

int main(void) {
    // Initialize hardware
    setupApp();
    __stack_chk_guard = random32();
    
    // Initialize OLED
    oledInit();
    oledClear();
    oledDrawStringCenter(0, "USB TEST", FONT_STANDARD);
    oledDrawStringCenter(16, "Firmware", FONT_STANDARD);
    oledDrawStringCenter(32, "Running...", FONT_STANDARD);
    oledRefresh();
    
    // Small delay after setup
    delay(1000);
    
    // Initialize timer
    timer_init();
    
    // Get unique ID
    desig_get_unique_id(storage_uuid);
    
    // Initialize USB
    oledDrawStringCenter(48, "Init USB...", FONT_STANDARD);
    oledRefresh();
    usbInit();
    
    // Main loop - blink OLED and poll USB
    uint32_t last_blink = 0;
    bool led_on = true;
    
    oledClear();
    oledDrawStringCenter(0, "USB TEST", FONT_STANDARD);
    oledDrawStringCenter(16, "Mode", FONT_STANDARD);
    oledRefresh();
    
    for (;;) {
        usbPoll();
        
        // Blink every 500ms to show we're alive
        uint32_t now = timer_ms();
        if (now - last_blink > 500) {
            last_blink = now;
            led_on = !led_on;
            
            if (led_on) {
                oledBox(120, 0, 127, 7, true);
            } else {
                oledBox(120, 0, 127, 7, false);
            }
            oledRefresh();
        }
    }

    return 0;
}
