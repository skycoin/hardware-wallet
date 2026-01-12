.syntax unified
.cpu cortex-m3
.thumb

.section .text.Reset_Handler
.global Reset_Handler
.type Reset_Handler, %function
Reset_Handler:
    @ Just call main.main directly, skip all runtime init
    bl main.main
    b .

.section .text.Default_Handler
.global Default_Handler
.type Default_Handler, %function
Default_Handler:
    b Default_Handler

@ Provide the handlers that the vector table needs
.weak NMI_Handler
.set NMI_Handler, Default_Handler
.weak HardFault_Handler
.set HardFault_Handler, Default_Handler
.weak MemoryManagement_Handler
.set MemoryManagement_Handler, Default_Handler
.weak BusFault_Handler
.set BusFault_Handler, Default_Handler
.weak UsageFault_Handler
.set UsageFault_Handler, Default_Handler
.weak SVC_Handler
.set SVC_Handler, Default_Handler
.weak DebugMon_Handler
.set DebugMon_Handler, Default_Handler
.weak PendSV_Handler
.set PendSV_Handler, Default_Handler
.weak SysTick_Handler
.set SysTick_Handler, Default_Handler
