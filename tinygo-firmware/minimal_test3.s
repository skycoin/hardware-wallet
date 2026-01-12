.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .word _stack_top          @ 0x00: Initial SP
    .word Reset_Handler       @ 0x04: Reset
    .word Default_Handler     @ 0x08: NMI
    .word Default_Handler     @ 0x0C: HardFault
    .word Default_Handler     @ 0x10: MemManage
    .word Default_Handler     @ 0x14: BusFault
    .word Default_Handler     @ 0x18: UsageFault
    .word 0                   @ 0x1C: Reserved
    .word 0                   @ 0x20: Reserved
    .word 0                   @ 0x24: Reserved
    .word 0                   @ 0x28: Reserved
    .word Default_Handler     @ 0x2C: SVCall
    .word Default_Handler     @ 0x30: Debug
    .word 0                   @ 0x34: Reserved
    .word Default_Handler     @ 0x38: PendSV
    .word Default_Handler     @ 0x3C: SysTick
    @ STM32F4 peripheral interrupts (fill to match TinyGo size ~0x1A8)
    .rept 90
    .word Default_Handler
    .endr

.section .text
.global Reset_Handler
.type Reset_Handler, %function
Reset_Handler:
    @ Zero BSS from 0x20001000 to 0x20001018 (same as TinyGo)
    ldr r0, =0x20001000
    ldr r1, =0x20001018
    movs r2, #0
bss_loop:
    cmp r0, r1
    beq bss_done
    stmia r0!, {r2}
    b bss_loop
bss_done:

    @ Set heapptr = heapStart (same as TinyGo)
    ldr r0, =0x20001000
    ldr r1, =0x20001018
    str r1, [r0, #0]

    @ Now toggle PB1 to show we made it
    ldr r0, =0x40023830       @ RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #0x02
    str r1, [r0]

    mov r2, #100
delay1:
    subs r2, r2, #1
    bne delay1

    ldr r0, =0x40020400       @ GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0C
    orr r1, r1, #0x04
    str r1, [r0]

    ldr r0, =0x40020418       @ GPIOB_BSRR
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

.global Default_Handler
.type Default_Handler, %function
Default_Handler:
    b Default_Handler

.end
