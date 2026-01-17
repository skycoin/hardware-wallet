// Pure assembly test - no TinyGo, just blink
// Assemble with: arm-none-eabi-as -mcpu=cortex-m3 -mthumb -o pure_asm_test.o pure_asm_test.s
// Link with: arm-none-eabi-ld -T minimal.ld -o pure_asm_test.elf pure_asm_test.o
// Convert: arm-none-eabi-objcopy -O binary pure_asm_test.elf pure_asm_test.bin

.syntax unified
.cpu cortex-m3
.thumb

// Vector table - must be at 0x08010000
.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .long 0x20020000          // Initial stack pointer (end of 128KB RAM)
    .long Reset_Handler + 1   // Reset handler (with Thumb bit)
    .long Default_Handler + 1 // NMI
    .long Default_Handler + 1 // HardFault
    .long Default_Handler + 1 // MemManage
    .long Default_Handler + 1 // BusFault
    .long Default_Handler + 1 // UsageFault
    .long 0, 0, 0, 0          // Reserved
    .long Default_Handler + 1 // SVCall
    .long Default_Handler + 1 // Debug
    .long 0                   // Reserved
    .long Default_Handler + 1 // PendSV
    .long Default_Handler + 1 // SysTick
    // Pad to 256 bytes for peripheral interrupts (not needed for this test)
    .space 176

.section .text
.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    // Enable GPIOB clock (bit 1 of RCC_AHB1ENR)
    ldr r0, =0x40023830     // RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #2          // Set bit 1 (GPIOB)
    str r1, [r0]

    // Short delay for clock to stabilize
    mov r2, #100
clk_delay:
    subs r2, #1
    bne clk_delay

    // Configure PB1 as output (MODER bits 3:2 = 01)
    ldr r0, =0x40020400     // GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0C       // Clear bits 3:2
    orr r1, r1, #0x04       // Set bit 2 (output mode)
    str r1, [r0]

main_loop:
    // Turn PB1 LOW (reset bit via BSRR high half)
    ldr r0, =0x40020418     // GPIOB_BSRR
    mov r1, #0x20000        // Bit 17 = reset PB1
    movt r1, #0x0002
    str r1, [r0]

    // Long delay
    ldr r2, =2000000
delay1:
    subs r2, #1
    bne delay1

    // Turn PB1 HIGH (set bit via BSRR low half)
    ldr r0, =0x40020418     // GPIOB_BSRR
    mov r1, #2              // Bit 1 = set PB1
    str r1, [r0]

    // Long delay
    ldr r2, =2000000
delay2:
    subs r2, #1
    bne delay2

    b main_loop

.global Default_Handler
.type Default_Handler, %function
.thumb_func
Default_Handler:
    // Blink fast if we hit an exception
    ldr r0, =0x40023830     // RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #2
    str r1, [r0]

    ldr r0, =0x40020400     // GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0C
    orr r1, r1, #0x04
    str r1, [r0]

fault_loop:
    ldr r0, =0x40020418
    mov r1, #0x20000
    movt r1, #0x0002
    str r1, [r0]
    ldr r2, =100000
f1: subs r2, #1
    bne f1
    ldr r0, =0x40020418
    mov r1, #2
    str r1, [r0]
    ldr r2, =100000
f2: subs r2, #1
    bne f2
    b fault_loop

.size Reset_Handler, .-Reset_Handler
.size Default_Handler, .-Default_Handler
