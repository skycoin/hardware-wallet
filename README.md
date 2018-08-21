# Skycoin hardware wallet

[![Build Status](https://travis-ci.com/skycoin/hardware-wallet.svg?branch=master)](https://travis-ci.com/skycoin/hardware-wallet)

This folder provides a firmware implementing skycoin features, and tools to test it.

The firmware itself is under [tiny-firmware](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware) folder.
The firmware had been copied and modified from [this repository](https://github.com/trezor/trezor-mcu).

The [skycoin-api](https://github.com/skycoin/hardware-wallet/tree/master/skycoin-api) folder contains the definition of the functions implementing the skycoin features.

The [go-api-for-hardware-wallet](https://github.com/skycoin/hardware-wallet/tree/master/go-api-for-hardware-wallet) defines functions that act as code example to communicate with the firmware using a golang code.

Follow up [the wiki](https://github.com/skycoin/hardware-wallet/wiki/Hardware-wallet-project-advancement) to keep track of project advancement.
See also the wiki about integration with skycoin web app [here](https://github.com/skycoin/hardware-wallet-go/wiki/Hardware-wallet-integration-with-skycoin-web-wallet).
