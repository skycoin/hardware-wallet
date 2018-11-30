# Skycoin firmware releases

The skycoin firmware is composed of two parts: the [bootloader](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware/bootloader) and the [firmware](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware/firmware).

When pluggin the device in, the bootloader runs first. Its only purpose it to check firmware's validity using skycoin signature.

The firmware is expected to have a header with proper MAGIC number and three signature slots. 

If the firmware does not have a valid signature in its header it is considered "not official". A warning will be displayed but the user can still skip it and use it anyway.

The "unofficial firmware warning", means that the firmware was not signed by Skycoin Foundation. 

Skycoin firmware is open source and it is easy to fork or copy offical repository and create concurrent firmware for the device. Skycoin Foundation however will not put its signature on it.

The skycoin hardware will be shipped with an immutable bootloader written in a protected memory that is impossible to re-write.

The firmware however can evolve over time and some solutions were developped to update an existing firmware (see [skycoin-cli](https://github.com/skycoin/hardware-wallet-go/)).

## Full-Firmware and bootloader folder

The [full-firmware](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware/full-firmware) and [bootloader](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware/bootloader) folders are here for developpement purpose. They are meant to be [flashed with st-link](https://github.com/skycoin/hardware-wallet/blob/master/tiny-firmware/README.md#3-how-to-burn-the-firmware-in-the-device) on a STM32 device in which the memory protection was not enabled yet.

You can check [here](https://github.com/skycoin/hardware-wallet/blob/master/tiny-firmware/README.md#3-how-to-burn-the-firmware-in-the-device) for instructions about how to burn a full firmware on a device.

## Firmware folder

 If you are a user of the skycoin electronic wallet and want to update your firmware. You can pick-up official and test releases from [this folder](https://github.com/skycoin/hardware-wallet/tree/master/tiny-firmware/firmware).

 To update firmware the device must be in "bootloader mode". Press both buttons, unplug your device and plug it back in. Then you can use [skycoin-cli](https://github.com/skycoin/hardware-wallet-go/) deviceFirmwareUpdate message to update the firmware.
