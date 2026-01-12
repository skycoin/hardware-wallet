// Diagnostic test - toggle RST, try SPI, toggle RST again
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

.equ RCC_AHB1ENR,    0x40023830
.equ RCC_APB2ENR,    0x40023844
.equ GPIOA_MODER,    0x40020000
.equ GPIOA_BSRR,     0x40020018
.equ GPIOB_MODER,    0x40020400
.equ GPIOB_BSRR,     0x40020418
.equ SPI1_CR1,       0x40013000
.equ SPI1_SR,        0x40013008
.equ SPI1_DR,        0x4001300C

.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    // Enable GPIO clocks
    ldr r0, =RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #0x03
    str r1, [r0]

    // Small delay
    ldr r2, =10000
1:  subs r2, #1
    bne 1b

    // Configure PB1 as output (RST)
    ldr r0, =GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #(3 << 2)
    orr r1, r1, #(1 << 2)
    str r1, [r0]

    // ========== PHASE 1: One long RST pulse ==========
    // This proves we're running - screen will blank briefly

    // RST LOW
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 17)      // Reset PB1
    str r1, [r0]

    // Hold for 500ms
    ldr r2, =2000000
2:  subs r2, #1
    bne 2b

    // RST HIGH
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 1)       // Set PB1
    str r1, [r0]

    // Wait 500ms
    ldr r2, =2000000
3:  subs r2, #1
    bne 3b

    // ========== PHASE 2: Two quick RST pulses ==========
    // This shows we got past phase 1

    mov r5, #2              // 2 pulses
phase2_loop:
    // RST LOW
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 17)
    str r1, [r0]

    ldr r2, =500000
4:  subs r2, #1
    bne 4b

    // RST HIGH
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 1)
    str r1, [r0]

    ldr r2, =500000
5:  subs r2, #1
    bne 5b

    subs r5, #1
    bne phase2_loop

    // Wait 1 second between phases
    ldr r2, =4000000
6:  subs r2, #1
    bne 6b

    // ========== PHASE 3: Three quick RST pulses ==========
    // Final confirmation

    mov r5, #3              // 3 pulses
phase3_loop:
    // RST LOW
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 17)
    str r1, [r0]

    ldr r2, =500000
7:  subs r2, #1
    bne 7b

    // RST HIGH
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 1)
    str r1, [r0]

    ldr r2, =500000
8:  subs r2, #1
    bne 8b

    subs r5, #1
    bne phase3_loop

    // ========== PHASE 4: Continuous slow blinking ==========
main_loop:
    // RST LOW
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 17)
    str r1, [r0]

    ldr r2, =4000000
9:  subs r2, #1
    bne 9b

    // RST HIGH
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 1)
    str r1, [r0]

    ldr r2, =4000000
10: subs r2, #1
    bne 10b

    b main_loop

.global Default_Handler
.type Default_Handler, %function
.thumb_func
Default_Handler:
    b Default_Handler

.size Reset_Handler, .-Reset_Handler
.size Default_Handler, .-Default_Handler
