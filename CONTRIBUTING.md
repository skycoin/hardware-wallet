
# Skywallet development guidelines

## How to start working with Skycoin HW

First of all you need to connect ST-LINK programmer to the hw to be able to change firmware and bootloader.
After the opening of the HW case, you can see 6 unconnected pins for of the bootloader.
Look at the back of the device and you will see that the #1 hole is marked by a square.
The rest are all circular. From the square the holes are 3v3, SWDIO, SWCLK, SWO, GND and RST.
Connect the 3V3, GND, SWCLK and SWDIO to the appropriate pins on the ST-LINK

### Building and loading bootloader and firmware

To build you project you need to execute the following commands:

- `make clean`
- `make clean-lib`
- `make build-deps`
- `make bootloader`
- `make firmware-deps`
- `make firmware`
- `make sign`
- `make full-firmware` - this command is available also with memory protect option

These are the main dependencies of the project which can be executed with the one following command ```c
make combined-release-mem-protect VERSION_FIRMWARE=1.1.0 VERSION_BOOTLOADER=1.2.0```

Now combined file with bootloader and firmware lies in the directory
`hardware-wallet/tiny-firmware/bootloader/combine/`
To flash the previous version and load the new one you need to run the following command.
`make st-flash`

NOTE: To load it properly you need to connect your HW with 6 pins and microB to your PC.

## CLA signing policies
Every contributor needs to sign the CLA. Upon creating a PR, you will be asked to agree to the Individual Contributor License Agreement, covering the fundamental legal questions around contributing to a Skycoin repo. Agreeing to the CLA is mandatory.

You can read more about contributing the contributing to all skycoin repositories [here](https://github.com/skycoin/skycoin/wiki/).

## Quick overview

The source code tree is composed of the following main parts:

- `README.md` provides an overview of the project.
- `Makefile` rules for project builds, testing and development commands.
- `releases` is used to store releaase binary files.
- `ci-scripts` tools for Travis CI and similar continuous integration environments.
- `skycoin-crypto` a C implementation of the [Skycoin cryptography API](https://github.com/skycoin/skycoin/tree/master/src/cipher).
- `tiny-firmware/bootloader` contains device bootloader source code .
- `tiny-firmware/emulator` contains the source code of the Skywallet emulator.
- `tiny-firmware/firmware` contains the source code of the Skywallet firmware.
- `tiny-firmware/gen` pixel art for the electronic wallet.
- `tiny-firmware/protob` message specifications for Skywallet communication.
- `tiny-firmware/vendor` third-party project packages used as dependencies.

### Bootloader

The Skywallet can enter in bootloader mode once it connected to the host machine with both buttons pressed. This mode might be required for some actions e.g. flashing a new firmware. Bootloader is also responsible for checking firmware while booting in user operational mode.

### Firmware

The firmware makes possible for the Skywallet to exchange messages with its peer. These [protocol buffer](https://developers.google.com/protocol-buffers/) messages are specified in [SkycoinProject/hardware-wallet-protob](https://github.com/SkycoinProject/hardware-wallet-protob) repository, which is included as a submodule at path `./tiny-firmware/protob` relative to repository root. Libraries are strongly advised to reuse these specifications to generate message-specific source code for a particular programming language. Use `make proto` target to generate the C code needed by firmware and bootloader.

At the core of the firmware , messages handlers are implemented in `tiny-firmware/firmware/fsm.c`. Function names should follow the convention `fsm_msgCamelCaseMsgName` and receive a single argument pointing at the corresponding protobuffer message `struct`. Message handler body should:

- Notifiy users of hard constraints e.g. request pin code before performing secure operations.
- Present selection and optional paths through command execution.
- Invoke business logic methods (defined with `Impl` suffix in `tiny-firmware/firmware/fsm_impl.c`).

**Important** `*Impl` functions in `fsm_impl.c` must not contain code for handling user interaction since they are meant to be used to implement [test cases](#testing).


### Gen
If some image needs to be used in the hardware wallet, you must add appropriate bitmap.
You can read more how to add a bitmap image [here](https://github.com/SkycoinProject/hardware-wallet/tree/develop/tiny-firmware/gen)
Fonts for the hardware wallet, are also generated in this section of the code base.

### Emulator
Instead of connecting hardware wallet and interacting directly with it, you run an emulator and work with it. An emulator is written using the SDL library for the graphics interface.


## Testing

Testing is performed on top of [check framework](https://libcheck.github.io/check/). Tests entry point is located at `./tiny-firmware/firmware/test_main.c`

### Steps to add new test files


- Create `test_FILENAME.c` and `test_FILENAME.h` from the C project template of your preference. Make sure to include the later in the former.
- Include `check.h`.
- Implement `void setup_tc_FILENAME(void)` and `void teardown_tc_FILENAME(void)` for preparing test fixture, if any.
- Define test blocks enclosed between `START_TEST(test_TCNAME)` and `END_TEST` macros.
- Define function `TCase *add_FILENAME_tests(TCase *tc)` doing at least the following:
  * Call `tcase_add_checked_fixture(tc, setup_tc_FILENAME, teardown_tc_FILENAME);`
  * Registers all test cases by invoking `tcase_add_test`.
  * Returns the same test case received as argument.
- Include `test_FILENAME.h` in `test_main.c`
- Add the statement `suite_add_tcase(s, add_FILENAME_tests(tcase_create("FILENAME")));` before returning from `test_suite()` function.

###  Test writing procedure

There are a few tests which are executed with  `make test` on the Hardware wallet.
- Proof of cryptography correctness
- Test of the firmware

These tests cover the most significant parts of the firmware, so they are necessary for every release build.
#### Cryptography test
First of all, occur the test of the cryptography. Because the lion's share of functionality is based on it.
We are using python unit tests for the cryptography, so all the values are pre-computed and if during the execution some of the tests are failed this is a sign that something is broken in skycoin cryptography.
The list of the functions which are tested:
- test_sign
- test_sha256sum
- test_generate_skycoin_pubkey_from_seckey
- test_base58_address_from_pubkey
- test_recover_pubkey_from_signed_digest
This specific order is used because of the dependencies of the function.
#### Firmware test
This part of the test consist of:
##### Timer test
If the timer is in an inactive state stopwatch_counter function must return the maximum value of the uint32.
Then the ascending and descending order of timer is tested.
Also, we must test the overflow of the timer. But these test cases are not implemented yet.
##### Finite state machine test

A finite state machine is responsible for interaction with the user. So all the functionality must behave properly, so as:
- Skycoin sign message must be returned in hexadecimal. Check message signature must fail in cases with invalid signed messages.
- Mnemonic generation must be appropriately implemented and the unexpected behave must be processed correctly.
- Correctly apply settings label and get the features of the HW and correctly handle the errors.
- All the PIN operations must behave correctly.
- The number of addresses doesn`t overflow, start index works correctly and all addresses are valid.
##### Droplet test
Checks that the string representation of the coin amount is valid on all buffer sizes.
##### PIN protection test
Tests that PIN matrix layout works well and checks input with wrong digits.




## Relationship to other projects

- [Hardware wallet daemon](https://github.com/SkycoinProject/hardware-wallet-daemon)
The hardware wallet daemon provides an HTTP API to interface with the wallets supported by skycoin. It uses the go bindings provided by the hardware wallet GO library.

- [Hardware wallet protobuffer](https://github.com/SkycoinProject/hardware-wallet-protob)
Protocol Buffer schemas for Skycoin hardware wallet communication and scripts for supporting multiple programming languages.

- [Hardware wallet GO library](https://github.com/SkycoinProject/hardware-wallet-go)
  Go bindings and CLI tool for the Skycoin hardware wallet.

- [Hardware wallet JS library](https://github.com/SkycoinProject/hardware-wallet-js)
  Javascript interface for the Skycoin hardware wallet
