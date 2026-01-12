// No-op test - just loop forever, don't touch any GPIO
// The bootloader screen should remain visible
.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .long 0x20020000
    .long Reset_Handler + 1
    .long Default_Handler + 1
    .long Default_Handler + 1
    .long Default_Handler + 1
    .long Default_Handler + 1
    .long Default_Handler + 1
    .long 0, 0, 0, 0
    .long Default_Handler + 1
    .long Default_Handler + 1
    .long 0
    .long Default_Handler + 1
    .long Default_Handler + 1
    .space 176

.section .text

.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    // Do absolutely nothing - just loop
    // The bootloader's OLED display should remain visible
loop:
    nop
    nop
    nop
    nop
    b loop

.global Default_Handler
.type Default_Handler, %function
.thumb_func
Default_Handler:
    b Default_Handler

.size Reset_Handler, .-Reset_Handler
.size Default_Handler, .-Default_Handler
