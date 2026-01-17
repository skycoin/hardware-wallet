.syntax unified
.cpu cortex-m3
.thumb

// Override TinyGo's Reset_Handler to bypass all runtime init
// This tests that hardware works when loaded via bootloader
.section .text.Reset_Handler
.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    // Set VTOR to point to our vector table at 0x08010000
    // This is critical for firmware loaded by bootloader
    ldr r0, =0xE000ED08     // VTOR address
    ldr r1, =0x08010000     // Our vector table location
    str r1, [r0]

    // Enable GPIOB clock
    ldr r0, =0x40023830     // RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #0x02       // Enable GPIOB
    str r1, [r0]

    // Small delay for clock to stabilize
    mov r2, #100
1:  subs r2, r2, #1
    bne 1b

    // Configure PB1 as output (OLED RST)
    ldr r0, =0x40020400     // GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0C       // Clear bits 2-3 (PB1 mode)
    orr r1, r1, #0x04       // Set as output (01)
    str r1, [r0]

    // Toggle PB1 forever
    ldr r0, =0x40020418     // GPIOB_BSRR
toggle_loop:
    mov r1, #0x02           // Set PB1 high
    str r1, [r0]
    ldr r2, =500000
2:  subs r2, r2, #1
    bne 2b

    movw r1, #0x0000
    movt r1, #0x0002        // 0x00020000 = Reset PB1 low
    str r1, [r0]
    ldr r2, =500000
3:  subs r2, r2, #1
    bne 3b

    b toggle_loop

.size Reset_Handler, .-Reset_Handler
