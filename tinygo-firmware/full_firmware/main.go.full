package main

import (
	"unsafe"
)

// Memory mapped register helper
func reg32(addr uint32) *uint32 {
	return (*uint32)(unsafe.Pointer(uintptr(addr)))
}

func regGet(addr uint32) uint32 {
	return *reg32(addr)
}

func regSet(addr uint32, val uint32) {
	*reg32(addr) = val
}

func regSetBits(addr uint32, bits uint32) {
	regSet(addr, regGet(addr)|bits)
}

func regClearBits(addr uint32, bits uint32) {
	regSet(addr, regGet(addr)&^bits)
}

// STM32F205 peripheral addresses
const (
	RCC_BASE   = 0x40023800
	GPIOA_BASE = 0x40020000
	GPIOC_BASE = 0x40020800
	USB_OTG_FS = 0x50000000

	// RCC
	RCC_AHB1ENR = RCC_BASE + 0x30
	RCC_AHB2ENR = RCC_BASE + 0x34

	// GPIOA
	GPIOA_MODER = GPIOA_BASE + 0x00
	GPIOA_PUPDR = GPIOA_BASE + 0x0C
	GPIOA_AFRH  = GPIOA_BASE + 0x24
	GPIOA_ODR   = GPIOA_BASE + 0x14

	// GPIOC (for LED)
	GPIOC_MODER = GPIOC_BASE + 0x00
	GPIOC_ODR   = GPIOC_BASE + 0x14

	// USB OTG FS registers
	USB_GCCFG     = USB_OTG_FS + 0x038
	USB_GRSTCTL   = USB_OTG_FS + 0x010
	USB_GUSBCFG   = USB_OTG_FS + 0x00C
	USB_GINTSTS   = USB_OTG_FS + 0x014
	USB_GINTMSK   = USB_OTG_FS + 0x018
	USB_GRXFSIZ   = USB_OTG_FS + 0x024
	USB_GRXSTSP   = USB_OTG_FS + 0x020
	USB_GAHBCFG   = USB_OTG_FS + 0x008
	USB_DCFG      = USB_OTG_FS + 0x800
	USB_DCTL      = USB_OTG_FS + 0x804
	USB_DSTS      = USB_OTG_FS + 0x808
	USB_CID       = USB_OTG_FS + 0x03C
	USB_HNPTXFSIZ = USB_OTG_FS + 0x028
	USB_PCGCCTL   = USB_OTG_FS + 0xE00
	USB_DAINT     = USB_OTG_FS + 0x818
	USB_DAINTMSK  = USB_OTG_FS + 0x81C
	USB_DIEPMSK   = USB_OTG_FS + 0x810
	USB_DOEPMSK   = USB_OTG_FS + 0x814

	// EP0 registers
	USB_DIEPCTL0  = USB_OTG_FS + 0x900
	USB_DOEPCTL0  = USB_OTG_FS + 0xB00
	USB_DOEPTSIZ0 = USB_OTG_FS + 0xB10
	USB_DIEPTSIZ0 = USB_OTG_FS + 0x910
	USB_FIFO0     = USB_OTG_FS + 0x1000
)

var (
	blinkCounter = uint32(0)
)

func delay(cycles uint32) {
	for i := uint32(0); i < cycles; i++ {
		// Volatile read to prevent optimization
		_ = regGet(USB_GINTSTS)
	}
}

func initLED() {
	// Enable GPIOC clock
	regSetBits(RCC_AHB1ENR, 1<<2) // GPIOC

	// Set PC13 as output
	moder := regGet(GPIOC_MODER)
	moder &^= (3 << 26) // Clear PC13 mode
	moder |= (1 << 26)  // Output mode
	regSet(GPIOC_MODER, moder)
}

func ledOn() {
	regSet(GPIOC_ODR, regGet(GPIOC_ODR)|(1<<13))
}

func ledOff() {
	regSet(GPIOC_ODR, regGet(GPIOC_ODR)&^(1<<13))
}

func ledToggle() {
	regSet(GPIOC_ODR, regGet(GPIOC_ODR)^(1<<13))
}

func initGPIO() {
	// Enable GPIOA clock
	regSetBits(RCC_AHB1ENR, 1<<0)

	delay(1000)

	// Configure PA10 (VBUS) as AF with pull-up
	moder := regGet(GPIOA_MODER)
	moder &^= (3 << 20) // Clear PA10
	moder |= (2 << 20)  // AF mode
	regSet(GPIOA_MODER, moder)

	// Set AF10 for PA10 (USB OTG)
	afrh := regGet(GPIOA_AFRH)
	afrh &^= (0xF << 8)
	afrh |= (10 << 8)
	regSet(GPIOA_AFRH, afrh)

	// Pull-up on PA10
	pupdr := regGet(GPIOA_PUPDR)
	pupdr &^= (3 << 20)
	pupdr |= (1 << 20)
	regSet(GPIOA_PUPDR, pupdr)
}

func main() {
	// Initialize OLED FIRST - so we can see boot progress
	oledInit()
	oledClear()
	oledDrawStringCenter(0, "SKYWALLET")
	oledDrawStringCenter(16, "TINYGO FW")
	oledDrawStringCenter(32, "BOOTING...")
	oledRefresh()

	println("Skywallet TinyGo Firmware v0.1.0")
	println("OLED initialized - boot message shown")

	// Small delay so user can see boot message
	delay(1000000)

	// Initialize LED
	initLED()
	ledOff()

	// Show GPIO init message
	oledClear()
	oledDrawStringCenter(0, "SKYWALLET")
	oledDrawStringCenter(16, "Init GPIO...")
	oledRefresh()

	// Initialize GPIO for USB
	initGPIO()

	// Show USB init message
	oledClear()
	oledDrawStringCenter(0, "SKYWALLET")
	oledDrawStringCenter(16, "Init USB...")
	oledRefresh()

	// Initialize USB device with HID support
	usbDeviceInit()

	// Show ready message
	layoutHome()

	println("Entering main loop...")
	println("Waiting for USB enumeration...")

	lastOledUpdate := uint32(0)

	// Main loop
	for {
		// Poll USB device
		usbDevicePoll()

		// Poll message system (handles incoming/outgoing messages)
		if isConfigured() {
			msgPoll()
		}

		// Slow blink when not configured, fast when configured
		blinkCounter++
		if isConfigured() {
			if blinkCounter%100000 == 0 {
				ledToggle()
			}
		} else {
			if blinkCounter%500000 == 0 {
				ledToggle()
			}
		}

		// Update OLED every 2 seconds
		if blinkCounter-lastOledUpdate > 2000000 {
			lastOledUpdate = blinkCounter
			layoutHome()
		}

		// Print status periodically
		if blinkCounter%5000000 == 0 {
			println("Status: configured=", isConfigured())
		}
	}
}
