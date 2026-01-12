// OLED test - display all pixels on
// This proves the firmware is running by showing a visible change
.syntax unified
.cpu cortex-m3
.thumb

// Vector table
.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .long 0x20020000          // Stack pointer
    .long Reset_Handler + 1   // Reset handler
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

// Register definitions
.equ RCC_AHB1ENR,    0x40023830
.equ RCC_APB2ENR,    0x40023844
.equ GPIOA_MODER,    0x40020000
.equ GPIOA_BSRR,     0x40020018
.equ GPIOB_MODER,    0x40020400
.equ GPIOB_BSRR,     0x40020418
.equ SPI1_CR1,       0x40013000
.equ SPI1_SR,        0x40013008
.equ SPI1_DR,        0x4001300C

// OLED commands
.equ OLED_DISPLAYALLON, 0xA5
.equ OLED_DISPLAYON,    0xAF
.equ OLED_NORMALDISPLAY, 0xA6

// Pin definitions
.equ PA4_CS,         4          // OLED CS on PA4
.equ PB0_DC,         0          // OLED DC on PB0
.equ PB1_RST,        1          // OLED RST on PB1

.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    // Enable GPIOA, GPIOB clocks
    ldr r0, =RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #0x03       // GPIOA and GPIOB
    str r1, [r0]

    // Enable SPI1 clock
    ldr r0, =RCC_APB2ENR
    ldr r1, [r0]
    orr r1, r1, #(1 << 12)  // SPI1EN
    str r1, [r0]

    // Short delay for clocks
    mov r2, #1000
1:  subs r2, #1
    bne 1b

    // Configure PA4 as output (CS)
    ldr r0, =GPIOA_MODER
    ldr r1, [r0]
    bic r1, r1, #(3 << 8)   // Clear bits 9:8
    orr r1, r1, #(1 << 8)   // Set bit 8 (output)
    str r1, [r0]

    // Configure PB0, PB1 as outputs (DC, RST)
    ldr r0, =GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0F       // Clear bits 3:0
    orr r1, r1, #0x05       // Set bits 2,0 (output mode for PB0, PB1)
    str r1, [r0]

    // Set RST high (out of reset)
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 1)       // Set PB1
    str r1, [r0]

    // Wait for OLED to stabilize after bootloader
    ldr r2, =100000
2:  subs r2, #1
    bne 2b

    // Send OLED_DISPLAYALLON command (0xA5) - turns all pixels ON
    // This gives visible feedback that our code is running

    // Set DC low (command mode)
    ldr r0, =GPIOB_BSRR
    mov r1, #(1 << 16)      // Reset PB0 (DC low)
    str r1, [r0]

    // Set CS low (select OLED)
    ldr r0, =GPIOA_BSRR
    mov r1, #(1 << 20)      // Reset PA4 (CS low)
    str r1, [r0]

    // Wait for SPI to be ready (TXE flag)
    ldr r0, =SPI1_SR
3:  ldr r1, [r0]
    tst r1, #2              // TXE bit
    beq 3b

    // Send DISPLAYALLON command
    ldr r0, =SPI1_DR
    mov r1, #OLED_DISPLAYALLON
    strb r1, [r0]

    // Wait for transmission complete (not busy)
    ldr r0, =SPI1_SR
4:  ldr r1, [r0]
    tst r1, #0x80           // BSY bit
    bne 4b

    // Set CS high (deselect)
    ldr r0, =GPIOA_BSRR
    mov r1, #(1 << 4)       // Set PA4 (CS high)
    str r1, [r0]

    // Now the OLED should show all pixels ON (white screen)
    // Loop forever
main_loop:
    b main_loop

.global Default_Handler
.type Default_Handler, %function
.thumb_func
Default_Handler:
    b Default_Handler

.size Reset_Handler, .-Reset_Handler
.size Default_Handler, .-Default_Handler
