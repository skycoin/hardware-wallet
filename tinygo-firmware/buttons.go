package main

import "unsafe"

// GPIO registers for button input (GPIOC)
const (
	GPIOC_BASE = 0x40020800
	GPIOC_MODER = GPIOC_BASE + 0x00 // Mode register
	GPIOC_IDR   = GPIOC_BASE + 0x10 // Input data register
	GPIOC_PUPDR = GPIOC_BASE + 0x0C // Pull-up/pull-down register

	// RCC for enabling GPIOC clock
	RCC_AHB1ENR_ADDR = 0x40023830

	// Button pins on GPIOC
	BTN_PIN_YES = 1 << 2 // PC2
	BTN_PIN_NO  = 1 << 5 // PC5
)

// ButtonState tracks button press state
type ButtonState struct {
	YesDown uint32 // Counter while Yes is held
	NoDown  uint32 // Counter while No is held
	YesUp   bool   // True on Yes release edge
	NoUp    bool   // True on No release edge
}

var button ButtonState
var btnLastState uint16 = BTN_PIN_YES | BTN_PIN_NO

// buttonInit initializes the button GPIO pins as inputs with pull-ups
func buttonInit() {
	// Enable GPIOC clock
	rcc := (*uint32)(unsafe.Pointer(uintptr(RCC_AHB1ENR_ADDR)))
	*rcc |= 1 << 2 // GPIOCEN

	// Small delay for clock to stabilize
	for i := 0; i < 100; i++ {
		// nop
	}

	// Configure PC2 and PC5 as inputs (MODER = 00)
	moder := (*uint32)(unsafe.Pointer(uintptr(GPIOC_MODER)))
	*moder &^= (3 << (2 * 2)) | (3 << (5 * 2)) // Clear bits for PC2 and PC5

	// Enable pull-up resistors (PUPDR = 01)
	pupdr := (*uint32)(unsafe.Pointer(uintptr(GPIOC_PUPDR)))
	*pupdr &^= (3 << (2 * 2)) | (3 << (5 * 2)) // Clear
	*pupdr |= (1 << (2 * 2)) | (1 << (5 * 2))  // Set pull-up
}

// buttonRead reads the current button state from GPIO
func buttonRead() uint16 {
	idr := (*uint32)(unsafe.Pointer(uintptr(GPIOC_IDR)))
	return uint16(*idr)
}

// buttonUpdate updates the button state structure
// Call this regularly from the main loop
func buttonUpdate() {
	state := buttonRead()

	// Yes button (PC2) - active low
	if (state & BTN_PIN_YES) == 0 {
		// Yes button is down
		if (btnLastState & BTN_PIN_YES) == 0 {
			// Was already down - increment counter
			if button.YesDown < 2000000000 {
				button.YesDown++
			}
			button.YesUp = false
		} else {
			// Just pressed
			button.YesDown = 0
			button.YesUp = false
		}
	} else {
		// Yes button is up
		if (btnLastState & BTN_PIN_YES) == 0 {
			// Just released
			button.YesDown = 0
			button.YesUp = true
		} else {
			// Was already up
			button.YesDown = 0
			button.YesUp = false
		}
	}

	// No button (PC5) - active low
	if (state & BTN_PIN_NO) == 0 {
		// No button is down
		if (btnLastState & BTN_PIN_NO) == 0 {
			// Was already down - increment counter
			if button.NoDown < 2000000000 {
				button.NoDown++
			}
			button.NoUp = false
		} else {
			// Just pressed
			button.NoDown = 0
			button.NoUp = false
		}
	} else {
		// No button is up
		if (btnLastState & BTN_PIN_NO) == 0 {
			// Just released
			button.NoDown = 0
			button.NoUp = true
		} else {
			// Was already up
			button.NoDown = 0
			button.NoUp = false
		}
	}

	btnLastState = state
}

// ButtonRequestType enum values are defined in protobuf.go

// protectState tracks button protection state machine
type ProtectState int

const (
	PROTECT_IDLE ProtectState = iota
	PROTECT_WAIT_ACK
	PROTECT_WAIT_BUTTON
)

var protectCurrentState ProtectState = PROTECT_IDLE
var protectConfirmOnly bool = false

// protectButtonStart initiates button protection
// Returns immediately - caller must poll for completion
func protectButtonStart(btnType uint32, confirmOnly bool) {
	protectCurrentState = PROTECT_WAIT_ACK
	protectConfirmOnly = confirmOnly

	// Clear button state
	buttonUpdate()
	button.YesUp = false
	button.NoUp = false

	// Send ButtonRequest
	sendButtonRequest(btnType)
}

// protectButtonPoll checks if button confirmation is complete
// Returns: 0 = still waiting, 1 = confirmed (Yes), -1 = cancelled (No)
func protectButtonPoll() int {
	switch protectCurrentState {
	case PROTECT_IDLE:
		return 0 // Not started

	case PROTECT_WAIT_ACK:
		// Check if we received ButtonAck
		// This is handled in dispatchMessage - set a flag there
		// For now, just check button state
		buttonUpdate()
		if button.YesUp {
			return 1
		}
		if !protectConfirmOnly && button.NoUp {
			protectCurrentState = PROTECT_IDLE
			return -1
		}
		return 0

	case PROTECT_WAIT_BUTTON:
		buttonUpdate()
		if button.YesUp {
			protectCurrentState = PROTECT_IDLE
			return 1
		}
		if !protectConfirmOnly && button.NoUp {
			protectCurrentState = PROTECT_IDLE
			return -1
		}
		return 0
	}

	return 0
}

// protectButtonReset resets the protection state
func protectButtonReset() {
	protectCurrentState = PROTECT_IDLE
}

// layoutConfirmSign shows a signing confirmation dialog
func layoutConfirmSign(action string, details string) {
	// Clear display
	oledClear()

	// Draw confirmation dialog
	oledDrawString(4, 0, "Confirm?")
	oledDrawString(4, 16, action)
	if len(details) > 20 {
		oledDrawString(4, 28, details[:20])
		if len(details) > 40 {
			oledDrawString(4, 40, details[20:40])
		} else {
			oledDrawString(4, 40, details[20:])
		}
	} else {
		oledDrawString(4, 28, details)
	}

	// Draw button labels
	oledDrawString(4, 56, "< No")
	oledDrawString(88, 56, "Yes >")

	oledRefresh()
}

// layoutConfirmTx shows a transaction confirmation dialog
func layoutConfirmTx(toAddress string, coins, hours uint64) {
	// Clear display
	oledClear()

	// Title
	oledDrawString(4, 0, "Confirm TX?")

	// Address (truncated)
	oledDrawString(4, 12, "To:")
	if len(toAddress) > 14 {
		oledDrawString(28, 12, toAddress[:14])
	} else {
		oledDrawString(28, 12, toAddress)
	}

	// Amount
	oledDrawString(4, 24, "SKY:")
	// Convert coins from droplets to SKY (1 SKY = 1000000 droplets)
	skyWhole := coins / 1000000
	skyFrac := (coins % 1000000) / 10000 // Two decimal places
	oledDrawInt(36, 24, int(skyWhole))
	oledDrawString(60, 24, ".")
	if skyFrac < 10 {
		oledDrawString(68, 24, "0")
		oledDrawInt(76, 24, int(skyFrac))
	} else {
		oledDrawInt(68, 24, int(skyFrac))
	}

	// Hours
	oledDrawString(4, 36, "Hours:")
	oledDrawInt(52, 36, int(hours))

	// Button labels
	oledDrawString(4, 56, "< No")
	oledDrawString(88, 56, "Yes >")

	oledRefresh()
}

// waitForButton waits for a button press and returns true for Yes, false for No
// This is a blocking function - use sparingly
func waitForButton(confirmOnly bool) bool {
	for {
		buttonUpdate()
		if button.YesUp {
			return true
		}
		if !confirmOnly && button.NoUp {
			return false
		}
		// Small delay
		for i := 0; i < 10000; i++ {
			// nop
		}
	}
}
