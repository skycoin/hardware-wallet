/* Minimal linker script for pure assembly test */
MEMORY
{
    FLASH (rx) : ORIGIN = 0x08010000, LENGTH = 448K
    RAM (rwx)  : ORIGIN = 0x20000000, LENGTH = 128K
}

SECTIONS
{
    .text : {
        *(.isr_vector)
        *(.text*)
    } > FLASH
}
