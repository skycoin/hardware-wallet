
# Skywallet development guidelines

## Quick overview

The source code tree is composed of the following main parts:

- `README.md` provides an overview of the project.
- `Makefile` rules for project builds, testing and development commands.
- `releases` is used to store releaase binary files.
- `ci-scripts` tools for Travis CI and similar continuous integration environments.
- `skycoin-api` a C implementation of the [Skycoin cryptography API](https://github.com/skycoin/skycoin/tree/master/src/cipher).
- `tiny-firmware/bootloader` contains device bootloader source code .
- `tiny-firmware/emulator` contains the source code of the Skywallet emulator.
- `tiny-firmware/firmware` contains the source code of the Skywallet firmware.
- `tiny-firmware/gen` pixel art for the electronic wallet.
- `tiny-firmware/protob` message specifications for Skywallet communication.
- `tiny-firmware/vendor` third-party project packages used as dependencies.

### Bootloader

The Skywallet can enter in bootloader mode once it connected to the host machine with both buttons pressed. This mode might be required for some actions e.g. flashing a new firmware. Bootloader is also responsible for checking firmware while booting in user operational mode.

### Firmware

The firmware makes possible for the Skywallet to exchange messages with its peer. These [protocol buffer](https://developers.google.com/protocol-buffers/) messages are specified in [skycoin/hardware-wallet-protob](https://github.com/skycoin/hardware-wallet-protob) repository, which is included as a submodule at path `./tiny-firmware/protob` relative to repository root. Libraries are strongly advised to reuse these specifications to generate message-specific source code for a particular programming language. Use `make proto` target to generate the C code needed by firmware and bootloader.

At the core of the firmware , messages handlers are implemented in `tiny-firmware/firmware/fsm.c`. Function names should follow the convention `fsm_msgCamelCaseMsgName` and receive a single argument pointing at the corresponding protobuffer message `struct`. Message handler body should:

- Notifiy users of hard constraints e.g. request pin code before performing secure operations.
- Present selection and optional paths through command execution.
- Invoke business logic methods (defined with `Impl` suffix in `tiny-firmware/firmware/fsm_impl.c`).

**Important** `*Impl` functions in `fsm_impl.c` must not contain code for handling user interaction since they are meant to be used to implement [test cases](#testing).

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

