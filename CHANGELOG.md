# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add an options `DISABLE_GETENTROPY_CONFIRM` to enable or disable at build time the button confirmation for get entropy msg.
- Skycoin logo in bootloader mode
- Enforce setting default device language to English
- Use`protobuf` file definitions as a `git submodule` from http://github.com/skycoin/hardware-wallet-protob/
- While building emulator specify path to SDL via `SDL_INCLUDE` environment variable.
- Add a "Frequently Asked Question" file.
- In `ApplySettings` message it is possible to set a label for identifying the device
- Return device label in `GetFeatures` message.
- If no label explicitly set it defaults to the same value of `device_ID` set in wipe function.
- Refactor inline functions to a more portable definition.
- Both `deviceSignMessage` and `deviceSignMessage` messages return the signed message serialized in hex format.
- Both `msgSkycoinSignMessage` and `msgSignTransactionMessageImpl` encode signature in hex format.
- Refactor build workflow, now the firmware is build as a separate library and this can be linked against a main for tests or the main to be use in production with the firmware.
- Split `fsm` into two files, `fsm_impl` and `fsm` itself, the functions from `fsm_impl` return an integer `err_code` value and in general are more easy to use in unit tests.
- Add some unit tests for `tiny-firmware` folder.
- Add `word_count` in `RecoveryDevice` and `GenerateMnemonic` messages to specify recovery seeds of either 12 or 24 words (i.e. reject 18 words seeds).
- Firmware and bootloader generation tested on linux and osx (travis-ci)

### Fixed

- Add a new function to convert from hex to bin, fixed bug #80.

### Changed

### Removed

- Installation instructions for `protobuf` related tools, use this from `hardware-wallet-protob` submodule.
- Remove support to recover device from words matrix. The only support method is scrambled words.
- Not possible to enforce BIP-39 wordlist during recovery process.
- Not possible to perform dry-run recovery workflow (for safe mnemonic validation)

### Fixed

### Security

