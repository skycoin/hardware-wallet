package main

import "unsafe"

// This file is named with underscore prefix so it sorts first alphabetically.
// Go init() functions run in filename order within a package, so this
// VTOR initialization runs before any other init().

// SCB_VTOR is the Vector Table Offset Register
const SCB_VTOR = 0xE000ED08

// FIRMWARE_VECTOR_TABLE is where our vector table is located
// This matches the FLASH_TEXT origin in the linker script
const FIRMWARE_VECTOR_TABLE = 0x08010100

func init() {
	// Set VTOR to point to our vector table IMMEDIATELY
	// This must happen before any interrupt can fire
	// Without this, interrupts use the wrong vector table and crash
	*(*uint32)(unsafe.Pointer(uintptr(SCB_VTOR))) = FIRMWARE_VECTOR_TABLE
}
