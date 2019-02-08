# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- [\#65](https://github.com/skycoin/hardware-wallet/issues/65):

  - `deviceSignMessage` and `deviceSignMessage` messages returns the signed message in hex format.

  - `msgSignTransactionMessageImpl` encode in hex format.

  - Refactor build scheme, now the firmware is build as a separate library and this can be linked against a main for tests or the main to be use in production with the firmware.

  - Refcator in `fsm` it was split into two files, `fsm_impl` and `fsm` it selft, the funtions from `fsm_impl` return some kind of `err_code` and in general are more easy to use in unit tests.

  - Add some unit tests for `tiny-firmware` folder.

  - `msgSkycoinSignMessage` return the signed message in hex format.

- Firmware and bootloader generation tested on linux and osx (travis-ci)

### Fixed

### Changed

### Removed

### Fixed

### Security

