package main

import "unsafe"

// This file is named with underscore prefix so it sorts first alphabetically.
// Go init() functions run in filename order within a package, so this
// VTOR initialization runs before any other init().

// SCB_VTOR is the Vector Table Offset Register
const SCB_VTOR = 0xE000ED08

// FIRMWARE_VECTOR_TABLE is where our vector table is located
// This matches the FLASH_TEXT origin in the linker script
const FIRMWARE_VECTOR_TABLE = 0x08010000

// RCC registers for clock configuration
const (
	RCC_BASE_ADDR    = 0x40023800
	RCC_CR           = RCC_BASE_ADDR + 0x00
	RCC_CFGR         = RCC_BASE_ADDR + 0x08
	RCC_AHB2ENR_ADDR = RCC_BASE_ADDR + 0x34

	// RNG registers
	RNG_BASE    = 0x50060800
	RNG_CR_ADDR = RNG_BASE + 0x00
	RNG_SR      = RNG_BASE + 0x04
)

func init() {
	// Set VTOR to point to our vector table IMMEDIATELY
	// This must happen before any interrupt can fire
	// Without this, interrupts use the wrong vector table and crash
	*(*uint32)(unsafe.Pointer(uintptr(SCB_VTOR))) = FIRMWARE_VECTOR_TABLE

	// Enable RNG clock (bit 6 of AHB2ENR)
	// TinyGo's runtime.initRand will call machine.GetRNG which needs this
	ahb2enr := (*uint32)(unsafe.Pointer(uintptr(RCC_AHB2ENR_ADDR)))
	*ahb2enr |= 1 << 6 // RNG clock enable

	// Enable RNG peripheral
	rngcr := (*uint32)(unsafe.Pointer(uintptr(RNG_CR_ADDR)))
	*rngcr |= 1 << 2 // RNGEN bit

	// Small delay for RNG to start up
	for i := 0; i < 1000; i++ {
		_ = *(*uint32)(unsafe.Pointer(uintptr(RNG_SR)))
	}
}
