/* Minimal linker script for STM32F205 firmware */

MEMORY
{
    FLASH (rx)  : ORIGIN = 0x08010000, LENGTH = 448K
    RAM (rwx)   : ORIGIN = 0x20000000, LENGTH = 128K
}

_stack_top = ORIGIN(RAM) + 4K;

SECTIONS
{
    .text :
    {
        KEEP(*(.isr_vector))
        *(.text)
        *(.text.*)
        *(.rodata)
        *(.rodata.*)
    } > FLASH

    .bss (NOLOAD) :
    {
        *(.bss)
        *(.bss.*)
    } > RAM
}
