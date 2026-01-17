package main

import (
	"runtime/volatile"
	"unsafe"
)

// STM32F205 RNG (Random Number Generator) registers
const (
	RNG_BASE = 0x50060800
	RNG_CR   = RNG_BASE + 0x00 // Control register
	RNG_SR   = RNG_BASE + 0x04 // Status register
	RNG_DR   = RNG_BASE + 0x08 // Data register

	// RNG_CR bits
	RNG_CR_RNGEN = 1 << 2 // RNG enable

	// RNG_SR bits
	RNG_SR_DRDY = 1 << 0 // Data ready
	RNG_SR_CECS = 1 << 1 // Clock error
	RNG_SR_SECS = 1 << 2 // Seed error
)

var rngInitialized bool

// rngReg returns a volatile register at the given address
func rngReg(addr uintptr) *volatile.Register32 {
	return (*volatile.Register32)(unsafe.Pointer(addr))
}

// rngInit initializes the hardware RNG
func rngInit() {
	if rngInitialized {
		return
	}

	// Enable RNG clock
	rngReg(RCC_AHB2ENR).SetBits(1 << 6)

	// Small delay for clock to stabilize
	for i := 0; i < 100; i++ {
		rngReg(RNG_SR).Get()
	}

	// Enable RNG
	rngReg(RNG_CR).Set(RNG_CR_RNGEN)

	rngInitialized = true
}

// rngGet32 returns a 32-bit random number from hardware RNG
func rngGet32() uint32 {
	rngInit()

	// Wait for data ready
	for rngReg(RNG_SR).Get()&RNG_SR_DRDY == 0 {
		// Check for errors
		sr := rngReg(RNG_SR).Get()
		if sr&(RNG_SR_CECS|RNG_SR_SECS) != 0 {
			// Clear errors and restart
			rngReg(RNG_SR).Set(0)
			rngReg(RNG_CR).Set(0)
			rngReg(RNG_CR).Set(RNG_CR_RNGEN)
		}
	}

	return rngReg(RNG_DR).Get()
}

// getEntropy fills a buffer with random bytes from hardware RNG
func getEntropy(buf []byte) {
	for i := 0; i < len(buf); i += 4 {
		val := rngGet32()
		for j := 0; j < 4 && i+j < len(buf); j++ {
			buf[i+j] = byte(val >> (j * 8))
		}
	}
}
