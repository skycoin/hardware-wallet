# Skycoin hardware wallet

## Overview

[![Build Status](https://travis-ci.com/skycoin/hardware-wallet.svg?branch=master)](https://travis-ci.com/skycoin/hardware-wallet)

This folder provides a firmware implementing skycoin features, and tools to test it.

The firmware itself is under [tiny-firmware](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware) folder.
The firmware had been copied and modified from [this repository](https://github.com/trezor/trezor-mcu).

The [skycoin-api](https://github.com/skycoin/hardware-wallet/tree/master/skycoin-api) folder contains the definition of the functions implementing the skycoin features.

The [skycoin-cli](https://github.com/skycoin/hardware-wallet-go/) defines golang functions that communicate with the firmware.

There is also a [javascript API](https://github.com/skycoin/hardware-wallet-js/).

Follow up [the wiki](https://github.com/skycoin/hardware-wallet/wiki/Hardware-wallet-project-advancement) to keep track of project advancement.

## Build instructions:

### Build and run emulator

```
make run-emulator
```

### Build a bootloader

```
make bootloader # Your firmware is tiny-firmware/bootloader/bootloader.bin
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
make full-firmware # this will create a tiny-firmware/bootloader/combine/combined.bin file
```
