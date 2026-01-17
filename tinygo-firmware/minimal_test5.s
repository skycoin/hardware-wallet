.syntax unified
.cpu cortex-m3
.thumb

.section .isr_vector, "a", %progbits
.global __isr_vector
__isr_vector:
    .word _stack_top
    .word Reset_Handler
    .word Default_Handler
    .word Default_Handler
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
.global Reset_Handler
.type Reset_Handler, %function
Reset_Handler:
    @ Same init as TinyGo: zero BSS, set heapptr
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

    @ NOW JUST LOOP FOREVER - same as TinyGo
loop_forever:
    b loop_forever

.global Default_Handler
.type Default_Handler, %function
Default_Handler:
    b Default_Handler

.end
