# Frequently Asked Question

## Security

### Random source:

- Does the hardware wallet have an entropy source?
  * Yes, the `True` random number generator peripheral implemented on wallet
    microcontrollers is based on an analog circuit. This circuit generates a 
    continuous analog noise that will be used by the RNG processing in order to 
    produce a 32-bit random number. To verify the true randomness of the numbers 
    generated a verification is performed based on the
    National Institute of Standards and Technology (NIST) Statistical Test Suite (STS) 
    SP 800-22rev1a (April 2010).
- Does the hardware wallet get entropy from the host machine?
  * Yes, an external random 32 bytes  buffer is used to increase internal entropy
    when performing cryptographically sensitive operations e.g. mnemonic generation
- How does the hardware wallet get entropy?
  * The hardware wallet generates internal entropy from a peripheral device. This value is
    [salted with several sources](https://security.stackexchange.com/questions/73588/does-too-long-a-salt-reduce-the-security-of-a-stored-password-hash)
    so as to make unfeasible some kinds of dictionary and lookup attacks (e.g. [rainbow tables](https://en.wikipedia.org/wiki/Rainbow_table) ).
    The salt is chosen in such a way that no two devices can generate the same value in (at least) the time frame of a human lifetime.
    Such values [might not be particularly random](https://security.stackexchange.com/questions/16117/in-hashing-does-it-matter-how-random-a-salt-is).
    Internal entropy is eventually combined with an external entropy received from the user host device.
    
### Salt sources
- What types of salt sources are considered ?
     1. Between devices (such as device UUID)
     2. Between device runs (at init time)
     3. Over time (after init, value continues to change)
- What are salt sources used in firmware ?
     1. MCU core registers
        * We use constant values of three registers, namely: 
        PC - shows which instruction perform next.
        SP - track the call stack
        LR - hold the address of the function.
    2. Device UUID
        * Every Microcontroller has its universal unique identifier which is stored at the specific location in memory, depending on different families.
        As it is unique in every device, it can be used as a good salt for the entropy. 
    3. SysTick timer
        * All the Microprocessor have it, regardless of the manufacturer. Systick timer is a part of the core.
    4. Unconnected GPIO pins
        * We configure a detached port as an input and then read the value from it. Because of specific physical processes appears noise, which goes with waves, which has minimal statistical dependence.
### Why do I see an inverted skycoin logo in bootloader?

If you see an inverted skycoin logo in bootloader mode like in the following image, maybe you have either flashed for development or not official device.

![Kiku](images/skycoin_logo_inverted_bootloader.jpg)

### What should I do if something fails?

If you are experiencing any issues:

- Determine if your particular case is mentioned in [troubleshooting section](#troubleshooting) and try to follow the corresponding instructions to fix it.
- Contact the developers via [Skycoin development channel in Telegram](https://t.me/skycoindev).

## Troubleshooting

### Skywallet not recognized by machine

If the Skywallet operates with an unofficial firmware, the user needs to confirm upon startup, that he wants to continue with this unofficial firmware and click `I will take the risk.` If that does not happen in under 2 seconds, the device often will not be recognized. Unplug und re-connect the device. Click the right buttons twice within 2 seconds.

## Cannot wipe the firmware on the device

When a firmware is installed on the device, the Go CLI can be used to erase the firmware installed. To do so, the device needs to be in bootlaoder mode. Unplug the device and re-connect it, while pressing both buttons. Then go ahead with wiping the firmware or updating the firmware.

## Firmware aborts the startup due to unofficial bootloader

The official firmware distributed and signed by Skycoin checks the integrity of the bootloader and aborts if the bootloader hash is not registered in the firmware. Developers can build firmware themselves, that does not perform this check and can be freely used. Refer to the main README for instructions on how to build the firmware without the hash check. 

