/*
 * This file is part of the SKYCOIN project, https://www.skycoin.net/
 *
 * Copyright (C) 2018 <contact@skycoin.net>
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


#include "factory_test.h"
#include "trezor.h"
#include "oled.h"
#if EMULATOR
#include "usb.h"
#else
#include "timer.h"
#endif
#include "buttons.h"
#include "layout.h"
#include "layout2.h"
#include "util.h"

#if !EMULATOR
void wait_ms(uint32_t millis) {
	uint32_t start = timer_ms();
	while ((timer_ms() - start) < millis) {
		delay(10);
	}
}
#else
#define wait_ms usbSleep
#endif

void factoryTest(void)
{

	layoutDialog(&bmp_icon_question, ("Cancel"), ("Test Device"), NULL, ("Do you really want to"), ("test your Wallet?"), NULL, NULL, NULL, NULL);

	// wait until NoButton is released
	do {
		wait_ms(5);
		buttonUpdate();
	} while (!button.YesUp);

	// wait for confirmation/cancellation of the dialog
	do {
		wait_ms(5);
		buttonUpdate();
	} while (!button.YesUp && !button.NoUp);

	if (button.YesUp) { // if user say yes

		factoryTest_screen();

		if(factoryTest_buttons(0)&&factoryTest_buttons(1))
		{
			layoutDialogSwipe(&bmp_icon_info, NULL,"Exit",NULL,NULL, ("Buttons are OK"),NULL,NULL,NULL,NULL);
		}
		else
		{
			layoutDialogSwipe(&bmp_icon_info,NULL,"Exit",NULL,NULL, ("Buttons error"),NULL,NULL,NULL,NULL);
		}

		do { // Back home
			wait_ms(5);
			buttonUpdate();
		} while (!button.YesUp);
	}
	return;
}

void factoryTest_screen(void)
{
	oledClear();
	oledRefresh();

	for (int i = 2; i < 12; i++) {

		wait_ms(1000);

		if (i%2)
		{
		oledBox(0, 0, 127, 63, false);
		oledRefresh();
		}
		else
		{
		oledBox(0, 0, 127, 63, true);
		oledRefresh();
		}
	}
	return;
}

bool factoryTest_buttons(bool buttonToTest)
{
	bool testResult=0;

	layoutDialog(&bmp_icon_question,((buttonToTest) ? NULL:"No"),((buttonToTest) ? "Yes":NULL),NULL,((buttonToTest) ? "Press Yes":" Press No"),(""), NULL, NULL, NULL, NULL);

	do {
		wait_ms(5);
		buttonUpdate();
	} while (!button.YesUp && !button.NoUp);

	if ((button.NoUp && !buttonToTest) || (button.YesUp && buttonToTest) ) {
		// Button is ok
		testResult=1;
	} else{
		// User is stupid
		testResult=0;
	}

	oledClear();
	oledRefresh();

	return testResult;
}
