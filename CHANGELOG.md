# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `deviceSignMessage` and `deviceSignMessage` messages return the signed message serialized in hex format.
-`msgSkycoinSignMessage` and `msgSignTransactionMessageImpl` encode signature in hex format.
- Refactor build workflow, now the firmware is build as a separate library and this can be linked against a main for tests or the main to be use in production with the firmware.
- Split `fsm` into two files, `fsm_impl` and `fsm` itself, the functions from `fsm_impl` return an integer `err_code` value and in general are more easy to use in unit tests.
- Add some unit tests for `tiny-firmware` folder.
- Firmware and bootloader generation tested on linux and osx (travis-ci)

### Fixed

### Changed

### Removed

### Fixed

### Security

