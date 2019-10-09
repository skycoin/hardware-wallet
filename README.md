![hardware-wallet-logo](https://user-images.githubusercontent.com/8619106/56054900-b1f9b680-5d75-11e9-8deb-cf657cfd0c55.png)

# Skycoin hardware wallet

[![Build Status](https://travis-ci.com/SkycoinProject/hardware-wallet.svg?branch=develop)](https://travis-ci.com/SkycoinProject/hardware-wallet)

## Table of contents

<!-- MarkdownTOC levels="1,2,3,4,5" autolink="true" bracket="round" -->

- [Overview](#overview)
- [FAQ](#faq)
- [Install tools](#install-tools)
- [Build instructions:](#build-instructions)
  - [Build and run emulator](#build-and-run-emulator)
  - [Build a bootloader](#build-a-bootloader)
  - [Build a bootloader with memory protection enabled](#build-a-bootloader-with-memory-protection-enabled)
  - [Build a firmware](#build-a-firmware)
  - [Sign firmware](#sign-firmware)
  - [Combine bootloader and firmware](#combine-bootloader-and-firmware)
  - [Combine a memory protected bootloader and firmware](#combine-a-memory-protected-bootloader-and-firmware)
- [Development guidelines](#development-guidelines)
  - [Versioning policies](#versioning-policies)
    - [Firmware version scheme](#firmware-version-scheme)
    - [Bootloader version scheme](#bootloader-version-scheme)
    - [Versioning libraries](#versioning-libraries)
  - [Running tests](#running-tests)
    - [Generating tests code coverage](#generating-tests-code-coverage)
  - [Releases](#releases)
    - [Update the version](#update-the-version)
    - [Pre-release testing](#pre-release-testing)
    - [Creating release builds](#creating-release-builds)

<!-- /MarkdownTOC -->

## Overview

This repo contains the firmware and bootloader for the Skywallet as well as tools to test and develop for the Skywallet. 
The firmware can be found in [/tiny-firmware](https://github.com/SkycoinProject/hardware-wallet/tree/master/tiny-firmware).
The firmware has been modified from [Trezor](https://github.com/trezor/trezor-mcu).

The [skycoin-api](https://github.com/SkycoinProject/hardware-wallet/tree/master/skycoin-api) folder contains the definition of the functions implementing the Skycoin features.
The [Skywallet Go CLI](https://github.com/SkycoinProject/hardware-wallet-go/releases) defines Golang functions that communicate with the firmware/bootloader.

## FAQ

[Frequently Asked Question](FAQ.md)

## Install tools

Get the development dependencies and tools from the [tiny-firware/README.md](https://github.com/SkycoinProject/hardware-wallet/blob/master/tiny-firmware/README.md) first, before continuing with the build instructions.

## Build instructions:

After cloning this repository, make sure the submodules are up-to-date by executing the following command:

```
git submodule update --init --recursive
```

Should you find any issues while running any of the commands that follow please consult [FAQ](FAQ.md) before [reporting a bug](ihttps://github.com/SkycoinProject/hardware-wallet/issues/new?assignees=&labels=bug&template=bug_report.md&title=).


### Build a bootloader

```
make bootloader # Your firmware is skybootloader-no-memory-protect.bin
```

### Build a bootloader with memory protection enabled

Careful if you flash and run that bootloader on the device it will activate a memory protection that will close access to flash memory.

You won't be able to flash your device with an st-link again.

```
make bootloader-mem-protect # Your firmware is bootloader-memory-protected.bin
```

### Build a firmware

```
make firmware  # Your firmware is tiny-firmware/skyfirmware.bin
```

### Sign firmware

Signs the firmware with the private key corresponding to the PubKeys that were registered in the bootlaoder during building. The PubKeys can be found in the project [Makefile](https://github.com/SkycoinProject/hardware-wallet/blob/develop/Makefile)
```
make sign # Your firmware is tiny-firmware/skyfirmware.bin
```

### Combine bootloader and firmware

This creates a combined firmware without memory protection.

```
make full-firmware # this will create a full-firmware-no-mem-protect.bin file
```

### Combine a memory protected bootloader and firmware

Caution: This combined firmware has memory protection enabled and therefore cannot be re-flashed. 

```
make full-firmware-mem-protect # this will create a full-firmware-memory-protected.bin file
```

### Build and run emulator

```
make clean && make run-emulator
```

In case of needing special compiler flags for the SDL library it is possible to provide them in `SDL_CFLAGS` variable. For instance , if SDL was installed with brew on Mac OS X then the following command execution would force searching for header files at the right location.

```
make clean && make run-emulator SDL_CFLAGS=-I$(brew --prefix sdl2)/include/SDL2
```

However for the default `brew` installation in practice this should not be needed since the value of `SDL_CFLAGS` defaults to `$(shell sdl2-config --cflags | sed 's/-D_THREAD_SAFE//g')`.


## Development guidelines

Code added in this repository should comply with the development guidelines documented in the [Skycoin wiki](https://github.com/skycoin/skycoin/wiki).

This project has two branches: `master` and `develop`.

- `develop` is the default branch and will always have the latest code.
- `master` will always be equal to the current stable release on the website, and should correspond with the latest release tag.

### Versioning policies

#### Firmware version scheme

The firmware follows [Semver](https://semver.org/).

The firmware binary filename is `skywallet-firmware-v$(VERSION_FIRMWARE).bin` e.g. `skywallet-firmware-v1.0.0.bin` .

#### Bootloader version scheme

The bootloder versioning is independent of the firmware versioning, but follows Semver as well. 

The bootloader binary filename is `skywallet-bootloader-mem-protect-v$(VERSION_BOOTLOADER).bin` if compiled with memory protection enabled it is `skywallet-bootloader-no-memory-protect-v$(VERSION_BOOTLOADER).bin`. For instance, `skywallet-bootloader-mem-protect-v1.0.2.bin` or  `skywallet-bootloader-no-memory-protect-v1.0.2.bin` could be bootloader file names.

#### Versioning libraries

In order to identify at first sight the features supported by a particular release of a client library, its major and minor version numbers should match the corresponding values of the version of the firmware they were built (tested) for. It is expected that the aforementioned library will be able to communicate to any firmware, as long as both versions (client and firmware) have the same major version number and firmware minor number is greater than the one of the library.

### Running tests

The project includes a test suite. In order to run it just execute the following command

```
make clean && make test
```

#### Generating tests code coverage

To generate code coverage html report you need to have `lcov` available in your `PATH`, in a debian based system you can run `apt install lcov`, lcov can be available using `brew` on osx too, but in the most general case you can follow the the official [install instructions](https://github.com/linux-test-project/lcov/blob/4ff2ed639ec25c271eb9aa2fcdadd30bfab33e4b/README).
After having this tool you can run `make check-coverage`, if not errors found you can find the result in `coverage/index.html`.


### Releases

#### Skycoin firmware releases

The Skywallet firmware is composed of two parts: the [bootloader](https://github.com/SkycoinProject/hardware-wallet/tree/master/tiny-firmware/bootloader) and the [firmware](https://github.com/SkycoinProject/hardware-wallet/tree/master/tiny-firmware/firmware).

Upon startup, the bootloader checks the validity of the firmware installed on the device. It checks whether the signatures of the firmware correspon to the PubKeys registered in the bootlaoder. The firmware is expected to have a header with proper MAGIC number and three signature slots.

If the firmware does not have a valid signature in its header it is considered **"not official"**. A warning will be displayed but the user can still skip it and use it anyway.

#### Update the version

0. If the `master` branch has commits that are not in `develop` (e.g. due to a hotfix applied to `master`), merge `master` into `develop` (and fix any build or test failures)
0. Switch to a new release branch named `release-X.Y.Z` for preparing the release.
0. Update `tiny-firmware/VERSION` and `tiny-firmware/bootloader/VERSION` with corresponding version numbers
0. Run `make build` to make sure that the code base is up to date
0. Update `CHANGELOG.md`: move the "unreleased" changes to the version and add the date.
0. Follow the steps in [pre-release testing](#pre-release-testing)
0. Make a PR merging the release branch into `master`
0. Ensure changes needed in protobuffer specs are merged into its `master` branch
0. Ensure protobuf specs sub-module will track changes from its `master` branch after merge
0. Review the PR and merge it
0. Tag the `master` branch with the version number. Version tags start with `v`, e.g. `v0.20.0`. Sign the tag. If you have your GPG key in github, creating a release on the Github website will automatically tag the release. It can be tagged from the command line with `git tag -as v0.20.0 $COMMIT_ID`, but Github will not recognize it as a "release".
0. Tag the changeset of the `protob` submodule checkout with the same version number as above.
0. Release builds are created and uploaded by travis. To do it manually, checkout the master branch and follow the [create release builds instructions](#creating-release-builds).
0. Checkout `develop` branch and bump `tiny-firmware/VERSION` and `tiny-firmware/bootloader/VERSION` to next [`dev` version number](https://www.python.org/dev/peps/pep-0440/#developmental-releases).

#### Pre-release testing

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

#### Creating release builds

The following instruction creates a full release:

```bash
make release
```
Firmware version will be retrieved automatically from `git`, and bootloader version will be take from `tiny-firmware/VERSION`.

## Responsible Disclosure

Security flaws in Skywallet source or infrastructure can be sent to security@skycoin.net.
Bounties are available for accepted critical bug reports.

PGP Key for signing:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWaj46RYJKwYBBAHaRw8BAQdApB44Kgde4Kiax3M9Ta+QbzKQQPoUHYP51fhN
1XTSbRi0I0daLUMgU0tZQ09JTiA8dG9rZW5AcHJvdG9ubWFpbC5jb20+iJYEExYK
AD4CGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AWIQQQpyK3by/+e9I4AiJYAWMb
0nx4dAUCWq/TNwUJCmzbzgAKCRBYAWMb0nx4dKzqAP4tKJIk1vV2bO60nYdEuFB8
FAgb5ITlkj9PyoXcunETVAEAhigo4miyE/nmE9JT3Q/ZAB40YXS6w3hWSl3YOF1P
VQq4OARZqPjpEgorBgEEAZdVAQUBAQdAa8NkEMxo0dr2x9PlNjTZ6/gGwhaf5OEG
t2sLnPtYxlcDAQgHiH4EGBYKACYCGwwWIQQQpyK3by/+e9I4AiJYAWMb0nx4dAUC
Wq/TTQUJCmzb5AAKCRBYAWMb0nx4dFPAAQD7otGsKbV70UopH+Xdq0CDTzWRbaGw
FAoZLIZRcFv8zwD/Z3i9NjKJ8+LS5oc8rn8yNx8xRS+8iXKQq55bDmz7Igw=
=5fwW
-----END PGP PUBLIC KEY BLOCK-----
```

Key ID: [0x5801631BD27C7874](https://pgp.mit.edu/pks/lookup?search=0x5801631BD27C7874&op=index)

The fingerprint for this key is:

```
pub   ed25519 2017-09-01 [SC] [expires: 2023-03-18]
      10A7 22B7 6F2F FE7B D238  0222 5801 631B D27C 7874
uid                      GZ-C SKYCOIN <token@protonmail.com>
sub   cv25519 2017-09-01 [E] [expires: 2023-03-18]
```

Keybase.io account: https://keybase.io/gzc

