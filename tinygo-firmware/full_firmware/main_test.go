// +build ignore

package main

import "unsafe"

// Minimal test firmware - just blink LED
// Build: tinygo build -o test.elf -target=./stm32f205.json -opt=z -gc=leaking main_test.go

const (
	SCB_VTOR    = 0xE000ED08
	RCC_BASE    = 0x40023800
	RCC_AHB1ENR = RCC_BASE + 0x30
	RCC_AHB2ENR = RCC_BASE + 0x34
	GPIOC_BASE  = 0x40020800
	GPIOC_MODER = GPIOC_BASE + 0x00
	GPIOC_ODR   = GPIOC_BASE + 0x14

	// RNG
	RNG_BASE = 0x50060800
	RNG_CR   = RNG_BASE + 0x00
	RNG_SR   = RNG_BASE + 0x04
	RNG_DR   = RNG_BASE + 0x08
)

func reg(addr uint32) *uint32 {
	return (*uint32)(unsafe.Pointer(uintptr(addr)))
}

func main() {
	// Set VTOR
	*reg(SCB_VTOR) = 0x08010000

	// Enable RNG clock and peripheral (for TinyGo runtime)
	*reg(RCC_AHB2ENR) |= 1 << 6
	*reg(RNG_CR) |= 1 << 2

	// Enable GPIOC clock
	*reg(RCC_AHB1ENR) |= 1 << 2

	// Small delay
	for i := 0; i < 10000; i++ {
		_ = *reg(RCC_AHB1ENR)
	}

	// Set PC13 as output
	moder := *reg(GPIOC_MODER)
	moder &^= 3 << 26
	moder |= 1 << 26
	*reg(GPIOC_MODER) = moder

	// Blink forever
	for {
		*reg(GPIOC_ODR) |= 1 << 13 // LED on
		for i := 0; i < 500000; i++ {
			_ = *reg(GPIOC_ODR)
		}
		*reg(GPIOC_ODR) &^= 1 << 13 // LED off
		for i := 0; i < 500000; i++ {
			_ = *reg(GPIOC_ODR)
		}
	}
}
