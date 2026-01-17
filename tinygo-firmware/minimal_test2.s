.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .word _stack_top          @ Initial SP
    .word Reset_Handler       @ Reset handler
    .word Default_Handler     @ NMI
    .word Default_Handler     @ HardFault
    .word Default_Handler     @ MemManage
    .word Default_Handler     @ BusFault
    .word Default_Handler     @ UsageFault
    .word 0, 0, 0, 0          @ Reserved
    .word Default_Handler     @ SVCall
    .word Default_Handler     @ Debug
    .word 0                   @ Reserved
    .word Default_Handler     @ PendSV
    .word Default_Handler     @ SysTick

.section .text
.global Reset_Handler
.type Reset_Handler, %function
Reset_Handler:
    @ Mimic TinyGo preinit: zero BSS from 0x20001000 to 0x20001018
    ldr r0, =0x20001000       @ _sbss
    ldr r1, =0x20001018       @ _ebss
    movs r2, #0
bss_loop:
    cmp r0, r1
    beq bss_done
    stmia r0!, {r2}           @ *r0++ = 0
    b bss_loop
bss_done:

    @ Now toggle PB1 to show we made it
    @ Enable GPIOB clock
    ldr r0, =0x40023830       @ RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #0x02         @ Enable GPIOB
    str r1, [r0]

    @ Small delay
    mov r2, #100
delay1:
    subs r2, r2, #1
    bne delay1

    @ Configure PB1 as output
    ldr r0, =0x40020400       @ GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0C
    orr r1, r1, #0x04
    str r1, [r0]

    @ Toggle PB1 forever
    ldr r0, =0x40020418       @ GPIOB_BSRR
toggle_loop:
    mov r1, #0x02             @ Set PB1 high
    str r1, [r0]
    ldr r2, =500000
delay_high:
    subs r2, r2, #1
    bne delay_high

    mov r1, #0x20000          @ Set PB1 low
    str r1, [r0]
    ldr r2, =500000
delay_low:
    subs r2, r2, #1
    bne delay_low

    b toggle_loop

.global Default_Handler
.type Default_Handler, %function
Default_Handler:
    b Default_Handler

.end
