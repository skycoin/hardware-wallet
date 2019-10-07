## Validate the TRNG

To be able to validate the device trng you need to install the following tools:

- `dieharder` (A testing and benchmarking tool for random number generators)
- `ent` (pseudorandom number sequence test)
- `rng-tools` (Check the randomness of data using FIPS 140-2 tests)

For example, in a debian based system you can run `apt install dieharder ent rng-tools`

In order to make the validation you need to build the firmware with `ENABLE_GETENTROPY` flag set o `1` and maybe you want to dissable button confirmation by seeting `DISABLE_GETENTROPY_CONFIRM` to `1`, the following is an example:

```bash
make clean
make firmware ENABLE_GETENTROPY=1 DISABLE_GETENTROPY_CONFIRM=1
```

After this , connect a Skywallet device and just run the following command:

```
make check-trng
```

After running the tools [some files](#Files-description) are generated and need to be analyzed by a human. Some of they are easy(because have an `Assessment` column) at a first look like for example:

```
#=============================================================================#
#            dieharder version 3.31.1 Copyright 2003 Robert G. Brown          #
#=============================================================================#
   rng_name    |           filename             |rands/second|
        mt19937|                 stm32_rng_7.dat|  1.40e+08  |
#=============================================================================#
        test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
   diehard_birthdays|   0|       100|     100|0.73855343|  PASSED
      diehard_operm5|   0|   1000000|     100|0.40846434|  PASSED
  diehard_rank_32x32|   0|     40000|     100|0.87409050|  PASSED
    diehard_rank_6x8|   0|    100000|     100|0.81487620|  PASSED
   diehard_bitstream|   0|   2097152|     100|0.97506327|  PASSED
        diehard_opso|   0|   2097152|     100|0.72414474|  PASSED
        diehard_oqso|   0|   2097152|     100|0.14038586|  PASSED
         diehard_dna|   0|   2097152|     100|0.29338685|  PASSED
diehard_count_1s_str|   0|    256000|     100|0.08300743|  PASSED
diehard_count_1s_byt|   0|    256000|     100|0.96142913|  PASSED
 diehard_parking_lot|   0|     12000|     100|0.43595334|  PASSED
    diehard_2dsphere|   2|      8000|     100|0.88771280|  PASSED
    diehard_3dsphere|   3|      4000|     100|0.09017234|  PASSED
     diehard_squeeze|   0|    100000|     100|0.56740432|  PASSED
        diehard_sums|   0|       100|     100|0.00071665|   WEAK
        diehard_runs|   0|    100000|     100|0.05569879|  PASSED
```
But in general a bit of research should be done looking at the files content. This feature come mainly from https://github.com/trezor/rng-test, so any advice from this repo is good as well

## Files description

- `dev_random_*.dat`: data generated from `/dev/random` (Linux kernel)

- `dev_urandom_*.dat`: data generated from `/dev/urandom` (Linux kernel)

- `stm32_rng_raw_*.dat`: data generated from STM32 chip using `random_buffer` function

- `stm32_rng_mixed_*.dat`: data generated from STM32 chip using `random_salted_buffer` function

- `*.dieharder`: output from **dieharder** program run for each `*.dat` file

- `*.ent`: output from **ent** program run for each `*.dat` file

- `*.rngtest`: output from **rngtest** program run for each `*.dat` file
