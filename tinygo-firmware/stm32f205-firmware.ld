/* Linker script for STM32F205 Skywallet firmware */

MEMORY
{
    FLASH_TEXT (rx) : ORIGIN = 0x08010000, LENGTH = 448K
    RAM (rwx)       : ORIGIN = 0x20000000, LENGTH = 128K
}

_stack_size = 16K;
_estack = ORIGIN(RAM) + LENGTH(RAM);

/* Include pre-assembled device startup code */
INPUT(device_stm32f205.o)

INCLUDE "targets/arm.ld"
