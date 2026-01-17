// Simplest possible GPIO toggle test
.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .long 0x20020000
    .long Reset_Handler + 1
    .long Fault_Handler + 1   // NMI
    .long Fault_Handler + 1   // HardFault
    .long Fault_Handler + 1   // MemManage
    .long Fault_Handler + 1   // BusFault
    .long Fault_Handler + 1   // UsageFault
    .space 228                 // Rest of vector table

.section .text

.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    // Step 1: Enable GPIOB clock
    // RCC_AHB1ENR = 0x40023830
    ldr r0, rcc_ahb1enr_addr
    ldr r1, [r0]
    orr r1, r1, #2          // Bit 1 = GPIOB
    str r1, [r0]

    // Tiny delay for clock to stabilize
    mov r2, #100
delay0:
    sub r2, r2, #1
    bne delay0

    // Step 2: Configure PB1 as output
    // GPIOB_MODER = 0x40020400
    ldr r0, gpiob_moder_addr
    ldr r1, [r0]
    // Clear bits 3:2, set bit 2 (output mode for pin 1)
    bic r1, r1, #0x0C
    orr r1, r1, #0x04
    str r1, [r0]

    // Step 3: Toggle PB1 using ODR
    // GPIOB_ODR = 0x40020414
    ldr r4, gpiob_odr_addr

toggle_loop:
    // Set PB1 HIGH
    ldr r1, [r4]
    orr r1, r1, #2
    str r1, [r4]

    // Long delay
    ldr r2, delay_val
delay1:
    sub r2, r2, #1
    bne delay1

    // Set PB1 LOW
    ldr r1, [r4]
    bic r1, r1, #2
    str r1, [r4]

    // Long delay
    ldr r2, delay_val
delay2:
    sub r2, r2, #1
    bne delay2

    b toggle_loop

// Fault handler - tight loop, different from default
.global Fault_Handler
.type Fault_Handler, %function
.thumb_func
Fault_Handler:
    b Fault_Handler

// Literal pool - placed right after code
.align 2
rcc_ahb1enr_addr:   .word 0x40023830
gpiob_moder_addr:   .word 0x40020400
gpiob_odr_addr:     .word 0x40020414
delay_val:          .word 4000000

.size Reset_Handler, .-Reset_Handler
