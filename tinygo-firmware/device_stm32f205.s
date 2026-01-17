// Device startup code for STM32F205 firmware loaded by bootloader
// This file is compiled as part of the Go package, no TinyGo modifications needed.

.syntax unified
.cpu cortex-m3
.thumb

// Entry point - minimal init then jump to Go main()
// Bypasses TinyGo's clock init which hangs on this hardware
.section .text.Reset_Handler_Entry
.global  Reset_Handler_Entry
.type    Reset_Handler_Entry, %function
.thumb_func
Reset_Handler_Entry:
    // Set up stack pointer (should already be set, but be safe)
    ldr r0, =_stack_top
    msr msp, r0

    // Set VTOR to point to our vector table at 0x08010000
    ldr r0, =0xE000ED08     // VTOR register address (SCB->VTOR)
    ldr r1, =0x08010000     // Our vector table location
    str r1, [r0]
    dsb                     // Data synchronization barrier
    isb                     // Instruction synchronization barrier

    // Initialize .data section (copy from flash to RAM)
    // This is what TinyGo's preinit() does
    ldr r0, =_sdata         // Destination (RAM)
    ldr r1, =_sidata        // Source (Flash)
    ldr r2, =_edata         // End of destination
copy_data:
    cmp r0, r2
    beq copy_data_done
    ldr r3, [r1], #4        // Load from flash, increment
    str r3, [r0], #4        // Store to RAM, increment
    b copy_data
copy_data_done:

    // Initialize .bss section (zero it)
    ldr r0, =_sbss          // Start of BSS
    ldr r1, =_ebss          // End of BSS
    movs r2, #0             // Zero value
zero_bss:
    cmp r0, r1
    beq zero_bss_done
    str r2, [r0], #4        // Store zero, increment
    b zero_bss
zero_bss_done:

    // Jump directly to GoMain, bypassing TinyGo's initAll
    // which tries to configure clocks and hangs
    ldr r0, =GoMain
    bx r0

    // Should never reach here
hang:
    b hang
.size Reset_Handler_Entry, .-Reset_Handler_Entry

// Default handler for interrupts - uses nop instead of wfe
// wfe can hang if no event is pending and SEV was never sent
.section .text.Default_Handler
.global  Default_Handler
.type    Default_Handler, %function
Default_Handler:
    nop
    b    Default_Handler
.size Default_Handler, .-Default_Handler

// Macro to define weak IRQ handlers that default to Default_Handler
.macro IRQ handler
    .weak  \handler
    .set   \handler, Default_Handler
.endm

// Vector table - must be at start of flash (0x08010000 for bootloader-loaded firmware)
.section .isr_vector, "a", %progbits
.global  __isr_vector
__isr_vector:
    // Cortex-M3 core vectors
    .long _stack_top              // Initial stack pointer
    .long Reset_Handler_Entry     // Reset handler (our wrapper that sets VTOR)
    .long NMI_Handler
    .long HardFault_Handler
    .long MemoryManagement_Handler
    .long BusFault_Handler
    .long UsageFault_Handler
    .long 0                       // Reserved
    .long 0                       // Reserved
    .long 0                       // Reserved
    .long 0                       // Reserved
    .long SVC_Handler
    .long DebugMon_Handler
    .long 0                       // Reserved
    .long PendSV_Handler
    .long SysTick_Handler

    // STM32F2xx/F4xx peripheral interrupts
    .long WWDG_IRQHandler
    .long PVD_IRQHandler
    .long TAMP_STAMP_IRQHandler
    .long RTC_WKUP_IRQHandler
    .long 0                       // Reserved (FLASH on F4)
    .long RCC_IRQHandler
    .long EXTI0_IRQHandler
    .long EXTI1_IRQHandler
    .long EXTI2_IRQHandler
    .long EXTI3_IRQHandler
    .long EXTI4_IRQHandler
    .long DMA1_Stream0_IRQHandler
    .long DMA1_Stream1_IRQHandler
    .long DMA1_Stream2_IRQHandler
    .long DMA1_Stream3_IRQHandler
    .long DMA1_Stream4_IRQHandler
    .long DMA1_Stream5_IRQHandler
    .long DMA1_Stream6_IRQHandler
    .long ADC_IRQHandler
    .long CAN1_TX_IRQHandler
    .long CAN1_RX0_IRQHandler
    .long CAN1_RX1_IRQHandler
    .long CAN1_SCE_IRQHandler
    .long EXTI9_5_IRQHandler
    .long TIM1_BRK_TIM9_IRQHandler
    .long TIM1_UP_TIM10_IRQHandler
    .long TIM1_TRG_COM_TIM11_IRQHandler
    .long TIM1_CC_IRQHandler
    .long TIM2_IRQHandler
    .long TIM3_IRQHandler
    .long TIM4_IRQHandler
    .long I2C1_EV_IRQHandler
    .long I2C1_ER_IRQHandler
    .long I2C2_EV_IRQHandler
    .long I2C2_ER_IRQHandler
    .long SPI1_IRQHandler
    .long SPI2_IRQHandler
    .long USART1_IRQHandler
    .long USART2_IRQHandler
    .long USART3_IRQHandler
    .long EXTI15_10_IRQHandler
    .long RTC_Alarm_IRQHandler
    .long OTG_FS_WKUP_IRQHandler
    .long TIM8_BRK_TIM12_IRQHandler
    .long TIM8_UP_TIM13_IRQHandler
    .long TIM8_TRG_COM_TIM14_IRQHandler
    .long TIM8_CC_IRQHandler
    .long DMA1_Stream7_IRQHandler
    .long FSMC_IRQHandler
    .long SDIO_IRQHandler
    .long TIM5_IRQHandler
    .long SPI3_IRQHandler
    .long UART4_IRQHandler
    .long UART5_IRQHandler
    .long TIM6_DAC_IRQHandler
    .long TIM7_IRQHandler
    .long DMA2_Stream0_IRQHandler
    .long DMA2_Stream1_IRQHandler
    .long DMA2_Stream2_IRQHandler
    .long DMA2_Stream3_IRQHandler
    .long DMA2_Stream4_IRQHandler
    .long ETH_IRQHandler
    .long ETH_WKUP_IRQHandler
    .long CAN2_TX_IRQHandler
    .long CAN2_RX0_IRQHandler
    .long CAN2_RX1_IRQHandler
    .long CAN2_SCE_IRQHandler
    .long OTG_FS_IRQHandler
    .long DMA2_Stream5_IRQHandler
    .long DMA2_Stream6_IRQHandler
    .long DMA2_Stream7_IRQHandler
    .long USART6_IRQHandler
    .long I2C3_EV_IRQHandler
    .long I2C3_ER_IRQHandler
    .long OTG_HS_EP1_OUT_IRQHandler
    .long OTG_HS_EP1_IN_IRQHandler
    .long OTG_HS_WKUP_IRQHandler
    .long OTG_HS_IRQHandler
    .long DCMI_IRQHandler
    .long CRYP_IRQHandler
    .long HASH_RNG_IRQHandler
    .long FPU_IRQHandler
    .long 0
    .long 0
    .long 0
    .long 0
    .long 0
    .long 0
    .long LCD_TFT_IRQHandler
    .long LCD_TFT_1_IRQHandler

.size __isr_vector, .-__isr_vector

// Weak definitions for all interrupt handlers
    IRQ NMI_Handler
    IRQ HardFault_Handler
    IRQ MemoryManagement_Handler
    IRQ BusFault_Handler
    IRQ UsageFault_Handler
    IRQ SVC_Handler
    IRQ DebugMon_Handler
    IRQ PendSV_Handler
    IRQ SysTick_Handler
    IRQ WWDG_IRQHandler
    IRQ PVD_IRQHandler
    IRQ TAMP_STAMP_IRQHandler
    IRQ RTC_WKUP_IRQHandler
    IRQ RCC_IRQHandler
    IRQ EXTI0_IRQHandler
    IRQ EXTI1_IRQHandler
    IRQ EXTI2_IRQHandler
    IRQ EXTI3_IRQHandler
    IRQ EXTI4_IRQHandler
    IRQ DMA1_Stream0_IRQHandler
    IRQ DMA1_Stream1_IRQHandler
    IRQ DMA1_Stream2_IRQHandler
    IRQ DMA1_Stream3_IRQHandler
    IRQ DMA1_Stream4_IRQHandler
    IRQ DMA1_Stream5_IRQHandler
    IRQ DMA1_Stream6_IRQHandler
    IRQ ADC_IRQHandler
    IRQ CAN1_TX_IRQHandler
    IRQ CAN1_RX0_IRQHandler
    IRQ CAN1_RX1_IRQHandler
    IRQ CAN1_SCE_IRQHandler
    IRQ EXTI9_5_IRQHandler
    IRQ TIM1_BRK_TIM9_IRQHandler
    IRQ TIM1_UP_TIM10_IRQHandler
    IRQ TIM1_TRG_COM_TIM11_IRQHandler
    IRQ TIM1_CC_IRQHandler
    IRQ TIM2_IRQHandler
    IRQ TIM3_IRQHandler
    IRQ TIM4_IRQHandler
    IRQ I2C1_EV_IRQHandler
    IRQ I2C1_ER_IRQHandler
    IRQ I2C2_EV_IRQHandler
    IRQ I2C2_ER_IRQHandler
    IRQ SPI1_IRQHandler
    IRQ SPI2_IRQHandler
    IRQ USART1_IRQHandler
    IRQ USART2_IRQHandler
    IRQ USART3_IRQHandler
    IRQ EXTI15_10_IRQHandler
    IRQ RTC_Alarm_IRQHandler
    IRQ OTG_FS_WKUP_IRQHandler
    IRQ TIM8_BRK_TIM12_IRQHandler
    IRQ TIM8_UP_TIM13_IRQHandler
    IRQ TIM8_TRG_COM_TIM14_IRQHandler
    IRQ TIM8_CC_IRQHandler
    IRQ DMA1_Stream7_IRQHandler
    IRQ FSMC_IRQHandler
    IRQ SDIO_IRQHandler
    IRQ TIM5_IRQHandler
    IRQ SPI3_IRQHandler
    IRQ UART4_IRQHandler
    IRQ UART5_IRQHandler
    IRQ TIM6_DAC_IRQHandler
    IRQ TIM7_IRQHandler
    IRQ DMA2_Stream0_IRQHandler
    IRQ DMA2_Stream1_IRQHandler
    IRQ DMA2_Stream2_IRQHandler
    IRQ DMA2_Stream3_IRQHandler
    IRQ DMA2_Stream4_IRQHandler
    IRQ ETH_IRQHandler
    IRQ ETH_WKUP_IRQHandler
    IRQ CAN2_TX_IRQHandler
    IRQ CAN2_RX0_IRQHandler
    IRQ CAN2_RX1_IRQHandler
    IRQ CAN2_SCE_IRQHandler
    IRQ OTG_FS_IRQHandler
    IRQ DMA2_Stream5_IRQHandler
    IRQ DMA2_Stream6_IRQHandler
    IRQ DMA2_Stream7_IRQHandler
    IRQ USART6_IRQHandler
    IRQ I2C3_EV_IRQHandler
    IRQ I2C3_ER_IRQHandler
    IRQ OTG_HS_EP1_OUT_IRQHandler
    IRQ OTG_HS_EP1_IN_IRQHandler
    IRQ OTG_HS_WKUP_IRQHandler
    IRQ OTG_HS_IRQHandler
    IRQ DCMI_IRQHandler
    IRQ CRYP_IRQHandler
    IRQ HASH_RNG_IRQHandler
    IRQ FPU_IRQHandler
    IRQ LCD_TFT_IRQHandler
    IRQ LCD_TFT_1_IRQHandler
