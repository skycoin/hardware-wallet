.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .word _stack_top
    .word Reset_Handler
    .word Default_Handler     @ NMI
    .word HardFault_Handler   @ HardFault - use TinyGo's version
    .word Default_Handler
    .word Default_Handler
    .word Default_Handler
    .word 0, 0, 0, 0
    .word Default_Handler
    .word Default_Handler
    .word 0
    .word Default_Handler
    .word Default_Handler
    .rept 90
    .word Default_Handler
    .endr

.section .text

@ TinyGo's Default_Handler: wfe + loop
.global Default_Handler
.type Default_Handler, %function
Default_Handler:
    wfe
    b Default_Handler

@ TinyGo's HardFault_Handler (simplified - just wfi loop)
.global HardFault_Handler
.type HardFault_Handler, %function
HardFault_Handler:
    wfi
    b HardFault_Handler

.global Reset_Handler
.type Reset_Handler, %function
Reset_Handler:
    @ Exact same init as TinyGo: zero BSS, set heapptr
    ldr r0, =0x20001000
    ldr r1, =0x20001018
    movs r2, #0
bss_loop:
    cmp r0, r1
    beq bss_done
    stmia r0!, {r2}
    b bss_loop
bss_done:
    ldr r0, =0x20001000
    ldr r1, =0x20001018
    str r1, [r0, #0]

    @ Toggle PB1
    ldr r0, =0x40023830
    ldr r1, [r0]
    orr r1, r1, #0x02
    str r1, [r0]
    mov r2, #100
delay1:
    subs r2, r2, #1
    bne delay1
    ldr r0, =0x40020400
    ldr r1, [r0]
    bic r1, r1, #0x0C
    orr r1, r1, #0x04
    str r1, [r0]
    ldr r0, =0x40020418
toggle_loop:
    mov r1, #0x02
    str r1, [r0]
    ldr r2, =500000
delay_high:
    subs r2, r2, #1
    bne delay_high
    mov r1, #0x20000
    str r1, [r0]
    ldr r2, =500000
delay_low:
    subs r2, r2, #1
    bne delay_low
    b toggle_loop

.end
