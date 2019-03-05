# Skycoin hardware wallet

[![Build Status](https://travis-ci.com/skycoin/hardware-wallet.svg?branch=master)](https://travis-ci.com/skycoin/hardware-wallet)

## Table of contents

<!-- MarkdownTOC levels="1,2,3,4,5" autolink="true" bracket="round" -->
- [Overview](#overview)
- [Install tools](#install-tools)
- [Build instructions:](#build-instructions)
  - [Build and run emulator](#build-and-run-emulator)
  - [Build a bootloader](#build-a-bootloader)
  - [Build a bootloader with memory protection enabled](#build-a-bootloader-with-memory-protection-enabled)
  - [Build a firmware](#build-a-firmware)
  - [Sign firmware](#sign-firmware)
  - [Combine bootloader and firmware](#combine-bootloader-and-firmware)
  - [Combine a memory protected bootloader and firmware](#combine-a-memory-protected-bootloader-and-firmware)
- [Running tests](#running-tests)
- [Releases](#releases)
  - [Update the version](#update-the-version)
  - [Pre-release testing](#pre-release-testing)
  - [Creating release builds](#creating-release-builds)
<!-- /MarkdownTOC -->

## Overview

This folder provides a firmware implementing skycoin features, and tools to test it.

The firmware itself is under [tiny-firmware](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware) folder.
The firmware had been copied and modified from [this repository](https://github.com/trezor/trezor-mcu).

The [skycoin-api](https://github.com/skycoin/hardware-wallet/tree/master/skycoin-api) folder contains the definition of the functions implementing the skycoin features.

The [skycoin-cli](https://github.com/skycoin/hardware-wallet-go/) defines golang functions that communicate with the firmware.

There is also a [javascript API](https://github.com/skycoin/hardware-wallet-js/).

Follow up [the wiki](https://github.com/skycoin/hardware-wallet/wiki/Hardware-wallet-project-advancement) to keep track of project advancement.

## Install tools

Follow the instructions written on [tiny-firware/README.md](https://github.com/skycoin/hardware-wallet/blob/master/tiny-firmware/README.md)

## Build instructions:

### Build and run emulator

```
make clean && make run-emulator
```

If SDL library was installed with brew on Mac OS X then try the following command instead

```
make clean && make run-emulator SDL_INCLUDE=$(brew --prefix sdl2)/include/SDL2
```

### Build a bootloader

```
make bootloader # Your firmware is bootloader-no-memory-protect.bin
```

### Build a bootloader with memory protection enabled

Careful if you flash and run that bootloader on the device it will activate a memory protection that will close access to flash memory.

You won't be able to flash your device with an st-link again.

```
make bootloader-mem-protect # Your firmware is bootloader-memory-protected.bin
```

### Build a firmware

```
make firmware  # Your firmware is tiny-firmware/skycoin.bin
```

### Sign firmware

```
make sign # Your firmware is tiny-firmware/skycoin.bin
```

### Combine bootloader and firmware

```
make full-firmware # this will create a full-firmware-no-mem-protect.bin file
```

### Combine a memory protected bootloader and firmware

Careful if you flash and run that bootloader on the device it will activate a memory protection that will close access to flash memory.

You won't be able to flash your device with an st-link again.

```
make full-firmware-mem-protect # this will create a full-firmware-memory-protected.bin file 
```

## Running tests

The project includes a test suite. In order to running just execute the following command

```
make test
```

## Releases

### Update the version

0. If the `master` branch has commits that are not in `develop` (e.g. due to a hotfix applied to `master`), merge `master` into `develop` (and fix any build or test failures)
0. Switch to a new release branch named `release-X.Y.Z` for preparing the release.
0. Update `tiny-firmware/VERSION` and `tiny-firmware/bootloader/VERSION` with corresponding version numbers
0. Run `make build` to make sure that the code base is up to date
0. Update `CHANGELOG.md`: move the "unreleased" changes to the version and add the date.
0. Follow the steps in [pre-release testing](#pre-release-testing)
0. Make a PR merging the release branch into `master`
0. Review the PR and merge it
0. Tag the `master` branch with the version number. Version tags start with `v`, e.g. `v0.20.0`. Sign the tag. If you have your GPG key in github, creating a release on the Github website will automatically tag the release. It can be tagged from the command line with `git tag -as v0.20.0 $COMMIT_ID`, but Github will not recognize it as a "release".
0. Release builds are created and uploaded by travis. To do it manually, checkout the master branch and follow the [create release builds instructions](#creating-release-builds).
0. Checkout `develop` branch and bump `tiny-firmware/VERSION` and `tiny-firmware/bootloader/VERSION` to next [`dev` version number](https://www.python.org/dev/peps/pep-0440/#developmental-releases).

### Pre-release testing

Once the candidate release build artifacts have been downloaded it is necessary to check once again that they behave according to specifications. The followinfg steps are aimed at ensuring this is the case. Execute 

0. Flash the device with latest versions of bootloader and firmware
0. Ensure you have a recent version of Skycoin desktop software in one of the following ways
  - build desktop wallet from source either following instructions [from master branch](https://github.com/skycoin/skycoin/blob/master/electron/README.md) or [from develop branch](https://github.com/skycoin/skycoin/blob/master/electron/README.md)
  - download Skycoin wallet from [official downloads page](https://www.skycoin.net/downloads/)
0. Open desktop wallet
0. Recover a test wallet with nonzero balance from seed to confirm wallet loading works
0. Send coins to another wallet to confirm spending works
0. Check that transferred amounts reported in transaction history are correct
0. Add a PIN to the hardware wallet 
0. Use the same recovery seed of the wallet configured in the Skywallet device and to load a wallet directly in desktop wallet
0. Send coins to another wallet again
0. Check transaction history once again
0. Wipe the wallet
0. Set up the hardware wallet with a random seed and write down the first address
0. Create a seed backup
0. Wipe the wallet and restore the seed. Check if the first address is equal to the one previously written
0. Repeat steps from the top but using combined bootloader + firmware image to flash the hardware wallet device.

### Creating release builds

The following instruction creates a full firmware with:
* firmware version: 1.1.0
* bootloader version: 1.2.0

```bash
make combined-release-mem-protect VERSION_FIRMWARE=1.1.0 VERSION_BOOTLOADER=1.2.0
```

Variables `VERSION_FIRMWARE` and `VERSION_BOOTLOADER` are optional and default to the contents of `tiny-firmware/VERSION` and `tiny-firmware/bootloader/VERSION` respectively.

