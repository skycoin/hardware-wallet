/* Linker script for STM32F205 Skywallet firmware */

MEMORY
{
    /* Firmware code starts at 0x08010100 (after 256-byte metadata header at 0x08010000) */
    FLASH_TEXT (rx) : ORIGIN = 0x08010100, LENGTH = 448K - 256
    RAM (rwx)       : ORIGIN = 0x20000000, LENGTH = 128K
}

/* Stack at END of RAM - ARM stacks grow downward */
_stack_size = 16K;

/* Override TinyGo's default: put stack at TOP of RAM, not bottom */
__stack_start = ORIGIN(RAM) + LENGTH(RAM);  /* 0x20020000 */
_stack_top = __stack_start;
_estack = __stack_start;

INCLUDE "/usr/lib/tinygo/targets/arm.ld"

/* Override .stack section to place at end of RAM */
SECTIONS
{
    .stack_override (NOLOAD) :
    {
        . = ORIGIN(RAM) + LENGTH(RAM) - _stack_size;
        . = ALIGN(8);
        _stack_start = .;
        . += _stack_size;
        . = ALIGN(8);
        _stack_top = .;
    } > RAM
}
INSERT AFTER .bss;
