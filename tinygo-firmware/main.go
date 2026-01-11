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

	// Display orientation will be fixed in oledSetPixel

	// Clear buffer and show initial text
	oledClear()

	// Draw title
	oledDrawString(4, 0, "TinyGo USB Test")
	oledRefresh()

	// Initialize USB device
	usbDeviceInit()

	// Show USB init complete
	oledDrawString(4, 8, "USB Init OK")

	// Test lines to check vertical boundaries (8-pixel spacing)
	oledDrawString(4, 32, "1")
	oledDrawString(4, 40, "2")
	oledDrawString(4, 48, "3")
	oledDrawString(4, 56, "4")
	oledRefresh()

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

// debugShowUSBEvent shows a USB event on the display with text
// Events: 1=Reset, 2=EnumDone, 3=Setup, 4=SendData
// NOTE: Does NOT call oledRefresh() - main loop handles that
func debugShowUSBEvent(event int) {
	y := DEBUG_START_Y + usbDebugLine*LINE_HEIGHT
	if y > 54 {
		// Clear area and restart
		for cy := DEBUG_START_Y; cy < 64; cy++ {
			for cx := 0; cx < 128; cx++ {
				oledSetPixel(cx, cy, false)
			}
		}
		usbDebugLine = 0
		y = DEBUG_START_Y
	}

	switch event {
	case 1:
		oledDrawString(4, y, "RST")
	case 2:
		oledDrawString(4, y, "ENUM")
	case 3:
		oledDrawString(4, y, "SETUP")
	case 4:
		oledDrawString(4, y, "SEND")
	case 5:
		oledDrawString(4, y, "ADDR")
	case 9:
		oledDrawString(4, y, "UNK")
	case 10:
		oledDrawString(4, y, "FEAT")
	case 11:
		oledDrawString(4, y, "RX")
	case 12:
		oledDrawString(4, y, "HID")
	case 13:
		oledDrawString(4, y, "CFG")
	case 14:
		oledDrawString(4, y, "TX")
	case 15:
		oledDrawString(4, y, "DONE")
	case 16:
		oledDrawString(4, y, "MSG!")
	default:
		oledDrawString(4, y, "E:")
		oledDrawInt(20, y, event)
	}

	usbDebugLine++
	oledRefresh()
}

// debugShowDescType shows the descriptor type being requested
func debugShowDescType(descType uint8) {
	y := DEBUG_START_Y + usbDebugLine*LINE_HEIGHT
	if y > 54 {
		for cy := DEBUG_START_Y; cy < 64; cy++ {
			for cx := 0; cx < 128; cx++ {
				oledSetPixel(cx, cy, false)
			}
		}
		usbDebugLine = 0
		y = DEBUG_START_Y
	}

	oledDrawString(4, y, "DT:")
	oledDrawInt(28, y, int(descType))

	usbDebugLine++
	oledRefresh()
}

// debugShowRequest shows the request type and bRequest
func debugShowRequest(bmReqType, bReq uint8) {
	y := 16 + usbDebugLine*8
	if y > 56 {
		for cy := 16; cy < 64; cy++ {
			for cx := 0; cx < 128; cx++ {
				oledSetPixel(cx, cy, false)
			}
		}
		usbDebugLine = 0
		y = 16
	}

	oledDrawString(4, y, "RQ:")
	oledDrawHex(28, y, uint32(bmReqType), 2)
	oledDrawString(52, y, "/")
	oledDrawHex(58, y, uint32(bReq), 2)

	usbDebugLine++
	oledRefresh()
}

// debugShowSetupCount shows SETUP packet count (updates in place)
func debugShowSetupCount(count int) {
	// Clear the count area and redraw
	for x := 70; x < 128; x++ {
		for y := 2; y < 9; y++ {
			oledSetPixel(x, y, false)
		}
	}
	oledDrawString(70, 2, "S:")
	oledDrawInt(88, 2, count)
	oledRefresh()
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
	// Debug: show first 3 bytes of packet
	debugShowUSBEvent(11) // HID received

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
	reg(GPIOA_BSRR).Set(1 << 4)  // CS high
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
