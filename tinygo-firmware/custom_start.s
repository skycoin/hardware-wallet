.syntax unified
.cpu cortex-m3
.thumb

@ Override TinyGo's Reset_Handler with a simple test
.section .text.Reset_Handler
.global Reset_Handler
.type Reset_Handler, %function
.thumb_func
Reset_Handler:
    @ Skip all TinyGo init, just toggle PB1 directly

    @ Enable GPIOB clock
    ldr r0, =0x40023830       @ RCC_AHB1ENR
    ldr r1, [r0]
    orr r1, r1, #0x02
    str r1, [r0]

    @ Small delay
    mov r2, #100
1:  subs r2, r2, #1
    bne 1b

    @ Configure PB1 as output
    ldr r0, =0x40020400       @ GPIOB_MODER
    ldr r1, [r0]
    bic r1, r1, #0x0C
    orr r1, r1, #0x04
    str r1, [r0]

    @ Toggle PB1 forever
    ldr r0, =0x40020418       @ GPIOB_BSRR
2:
    mov r1, #0x02             @ Set PB1 high
    str r1, [r0]
    ldr r2, =500000
3:  subs r2, r2, #1
    bne 3b

    mov r1, #0x20000          @ Set PB1 low
    str r1, [r0]
    ldr r2, =500000
4:  subs r2, r2, #1
    bne 4b

    b 2b
