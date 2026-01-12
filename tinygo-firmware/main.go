package main

import (
	"runtime/volatile"
	"unsafe"
)

//export GoMain
func GoMain() {
	// Don't re-init OLED - bootloader already did it
	// Just enable SPI and send data

	initSPI()

	// Initialize button input
	buttonInit()

	// Initialize storage
	storageInit()

	// Initialize USB device
	usbDeviceInit()

	// Show appropriate homescreen
	layoutHome()

	// Main loop - poll USB
	for {
		usbDevicePoll()

		// Check for received HID packets
		if ep1HasPacket() {
			pkt := ep1GetPacket()
			if pkt != nil {
				handleHIDPacket(pkt)
			}
		}
	}
}

// layoutHome shows the home screen based on device state
func layoutHome() {
	oledClear()

	// Draw Skycoin logo area (simple text for now)
	oledDrawString(28, 8, "SKYCOIN")
	oledDrawString(20, 20, "Hardware Wallet")

	// Show status based on initialization
	if storageIsInitialized() {
		oledDrawString(40, 40, "Ready")
	} else {
		oledDrawString(24, 40, "Not initialized")
		oledDrawString(28, 52, "Needs seed")
	}

	oledRefresh()
}

// drawDebugMarker draws a debug marker (number of vertical lines)
func drawDebugMarker(x, y int, count int) {
	for i := 0; i < count; i++ {
		for j := 0; j < 8; j++ {
			oledSetPixel(x+i*3, y+j, true)
		}
	}
}

// USB debug line position
var usbDebugLine = 0

// Line spacing for 8-pixel font
const LINE_HEIGHT = 8
const DEBUG_START_Y = 16 // After 2 title lines at y=0 and y=8

// displayNeedsRefresh is set when debug functions update the buffer
var displayNeedsRefresh = false

// debugShowUSBEvent shows a USB event on the display (disabled for production)
func debugShowUSBEvent(event int) {
	// Debug output disabled - homescreen should remain visible
	_ = event
}

// debugShowDescType shows the descriptor type being requested (disabled)
func debugShowDescType(descType uint8) {
	_ = descType
}

// debugShowRequest shows the request type and bRequest (disabled)
func debugShowRequest(bmReqType, bReq uint8) {
	_ = bmReqType
	_ = bReq
}

// debugShowSetupCount shows SETUP packet count (disabled)
func debugShowSetupCount(count int) {
	_ = count
}

// drawUSBIndicator draws a simple USB status indicator
func drawUSBIndicator(x, y int, connected bool) {
	// Draw a small rectangle as indicator
	// 8x8 box
	for i := 0; i < 8; i++ {
		oledSetPixel(x+i, y, true)   // Top
		oledSetPixel(x+i, y+7, true) // Bottom
	}
	for i := 0; i < 8; i++ {
		oledSetPixel(x, y+i, true)   // Left
		oledSetPixel(x+7, y+i, true) // Right
	}
	// Fill if connected
	if connected {
		for i := 2; i < 6; i++ {
			for j := 2; j < 6; j++ {
				oledSetPixel(x+i, y+j, true)
			}
		}
	}
}

// handleHIDPacket handles a received HID packet
func handleHIDPacket(pkt *[64]byte) {
	// Process through message protocol
	if msgReadPacket(pkt) {
		// Complete message received - dispatch it
		dispatchMessage()
	}

	// Send any pending output packets (one at a time, wait for each)
	for msgHasPendingOutput() {
		outPkt := msgGetNextPacket()
		if outPkt != nil {
			// Busy-wait until send succeeds (like C firmware)
			for !ep1SendPacket(outPkt) {
				usbDevicePoll() // Poll to clear ep1TxPending when transfer completes
			}
		}
	}
}

func main() {
	GoMain()
}

func reg(addr uintptr) *volatile.Register32 {
	return (*volatile.Register32)(unsafe.Pointer(addr))
}

const (
	RCC_APB2ENR uintptr = 0x40023844
	GPIOA_BSRR  uintptr = 0x40020018
	GPIOB_BSRR  uintptr = 0x40020418
	SPI1_CR1    uintptr = 0x40013000
	SPI1_SR     uintptr = 0x40013008
	SPI1_DR     uintptr = 0x4001300C
)

const (
	OLED_WIDTH   = 128
	OLED_HEIGHT  = 64
	OLED_BUFSIZE = OLED_WIDTH * OLED_HEIGHT / 8
)

var oledBuffer [OLED_BUFSIZE]byte

const (
	OLED_SETLOWCOLUMN  = 0x00
	OLED_SETHIGHCOLUMN = 0x10
	OLED_SETSTARTLINE  = 0x40
	OLED_SEGREMAP      = 0xA0
	OLED_COMSCANINC    = 0xC0
	OLED_COMSCANDEC    = 0xC8
)

func initSPI() {
	// Make sure SPI1 clock is enabled
	reg(RCC_APB2ENR).SetBits(1 << 12)

	// Small delay
	for i := 0; i < 1000; i++ {
		reg(SPI1_SR).Get()
	}

	// Enable SPI if not already
	cr1 := reg(SPI1_CR1).Get()
	if cr1&(1<<6) == 0 {
		reg(SPI1_CR1).Set((1 << 6) | (1 << 2) | (3 << 3))
	}

	// Configure display for 180-degree rotation
	oledCmd(0xA1) // SEGREMAP with flip
	oledCmd(0xC8) // COMSCANDEC
}

func spiSend(data byte) {
	for reg(SPI1_SR).Get()&0x02 == 0 {
	}
	reg(SPI1_DR).Set(uint32(data))
	for reg(SPI1_SR).Get()&0x80 != 0 {
	}
}

func oledCmd(cmd byte) {
	reg(GPIOB_BSRR).Set(1 << 16) // DC low
	reg(GPIOA_BSRR).Set(1 << 20) // CS low
	spiSend(cmd)
	reg(GPIOA_BSRR).Set(1 << 4) // CS high
}

func oledClear() {
	for i := range oledBuffer {
		oledBuffer[i] = 0
	}
}

func oledSetPixel(x, y int, on bool) {
	if x < 0 || x >= OLED_WIDTH || y < 0 || y >= OLED_HEIGHT {
		return
	}
	// Reversed buffer index
	idx := OLED_BUFSIZE - 1 - x - (y/8)*OLED_WIDTH
	// Shift bit order: rows 0-6 → bits 6-0, row 7 → bit 7
	bit := uint((6 - y%8 + 8) % 8)
	if on {
		oledBuffer[idx] |= 1 << bit
	} else {
		oledBuffer[idx] &^= 1 << bit
	}
}

func oledRefresh() {
	// Set address pointers
	oledCmd(OLED_SETLOWCOLUMN | 0x00)
	oledCmd(OLED_SETHIGHCOLUMN | 0x00)
	oledCmd(OLED_SETSTARTLINE | 0x00)

	// Send pixel data
	reg(GPIOB_BSRR).Set(1 << 0)  // DC high (data mode)
	reg(GPIOA_BSRR).Set(1 << 20) // CS low

	for i := 0; i < OLED_BUFSIZE; i++ {
		spiSend(oledBuffer[i])
	}

	reg(GPIOA_BSRR).Set(1 << 4)  // CS high
	reg(GPIOB_BSRR).Set(1 << 16) // DC low
}
