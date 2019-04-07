## Files description

- `dev_random_*.dat`: data generated from `/dev/random` (Linux kernel)

- `dev_urandom_*.dat`: data generated from `/dev/urandom` (Linux kernel)

- `stm32_rng_raw_*.dat`: data generated from STM32 chip using `random_buffer` function

- `stm32_rng_mixed_*.dat`: data generated from STM32 chip using `random_salted_buffer` function

- `*.dieharder`: output from **dieharder** program run for each `*.dat` file

- `*.ent`: output from **ent** program run for each `*.dat` file

- `*.rngtest`: output from **rngtest** program run for each `*.dat` file
