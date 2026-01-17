//go:build ignore

package main

import "unsafe"

// Minimal firmware to test if TinyGo can even start on this hardware
// Build with: tinygo build -o minimal.elf -target=./stm32f205.json -opt=z -gc=leaking main_minimal.go

func reg32(addr uint32) *uint32 {
	return (*uint32)(unsafe.Pointer(uintptr(addr)))
}

const (
	// SCB VTOR
	SCB_VTOR = 0xE000ED08
	FW_VTOR  = 0x08010100

	// RCC
	RCC_BASE    = 0x40023800
	RCC_AHB1ENR = RCC_BASE + 0x30

	// GPIOC for LED on PC13
	GPIOC_BASE  = 0x40020800
	GPIOC_MODER = GPIOC_BASE + 0x00
	GPIOC_ODR   = GPIOC_BASE + 0x14
)

func main() {
	// Set VTOR immediately
	*reg32(SCB_VTOR) = FW_VTOR

	// Enable GPIOC clock
	*reg32(RCC_AHB1ENR) |= 1 << 2

	// Small delay for clock to stabilize
	for i := 0; i < 1000; i++ {
		_ = *reg32(RCC_AHB1ENR)
	}

	// Set PC13 as output
	moder := *reg32(GPIOC_MODER)
	moder &^= 3 << 26
	moder |= 1 << 26
	*reg32(GPIOC_MODER) = moder

	// Blink forever
	for {
		// LED on
		*reg32(GPIOC_ODR) |= 1 << 13
		for i := 0; i < 500000; i++ {
			_ = *reg32(GPIOC_ODR)
		}
		// LED off
		*reg32(GPIOC_ODR) &^= 1 << 13
		for i := 0; i < 500000; i++ {
			_ = *reg32(GPIOC_ODR)
		}
	}
}
