/* Linker script for STM32F205RG - Skywallet firmware at 0x08010000 */

MEMORY
{
    /* Firmware starts at 0x08010000 after bootloader */
    FLASH (rx)  : ORIGIN = 0x08010000, LENGTH = 448K
    RAM (rwx)   : ORIGIN = 0x20000000, LENGTH = 128K
}

/* Entry point after bootloader jump */
ENTRY(Reset_Handler)

/* Top of stack at end of RAM */
_stack_size = 16K;
_estack = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
    /* Vector table and code */
    .text :
    {
        KEEP(*(.isr_vector))
        *(.text*)
        *(.rodata*)
        . = ALIGN(4);
        _etext = .;
    } > FLASH

    /* Data initialization */
    .data : AT(ADDR(.text) + SIZEOF(.text))
    {
        _sdata = .;
        *(.data*)
        . = ALIGN(4);
        _edata = .;
    } > RAM

    /* Uninitialized data */
    .bss :
    {
        _sbss = .;
        *(.bss*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = .;
    } > RAM

    /* Heap */
    .heap :
    {
        . = ALIGN(4);
        _heap_start = .;
        . = . + (LENGTH(RAM) - SIZEOF(.data) - SIZEOF(.bss) - _stack_size);
        . = ALIGN(4);
        _heap_end = .;
    } > RAM

    /* Stack */
    .stack :
    {
        . = ALIGN(8);
        . = . + _stack_size;
        . = ALIGN(8);
    } > RAM
}
