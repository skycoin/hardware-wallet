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

	// Clear buffer and set a pattern
	oledClear()

	// Draw a border around the screen
	for x := 0; x < 128; x++ {
		oledSetPixel(x, 0, true)      // Top edge
		oledSetPixel(x, 63, true)     // Bottom edge
	}
	for y := 0; y < 64; y++ {
		oledSetPixel(0, y, true)      // Left edge
		oledSetPixel(127, y, true)    // Right edge
	}

	// Draw an X in the middle
	for i := 0; i < 40; i++ {
		oledSetPixel(44+i, 12+i, true)
		oledSetPixel(44+i, 52-i, true)
	}

	oledRefresh()

	for {
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
	idx := x + (y/8)*OLED_WIDTH
	bit := uint(y) % 8
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
