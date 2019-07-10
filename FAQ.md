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
#### Salt sources
- MCU core registers
  * We use constant values of three registers, namely: 
    PC - shows which instruction perform next.
    SP - track the call stack
    LR - hold the address of the function.
- Device UUID
  * Every Microcontroller has its universal unique identifier which is stored at the specific location in memory, depending on different families.
    As it is unique in every device, it can be used as a good salt for the entropy.
- RTC(Real Time Clock) 
- SysTick timer
  * All the Microprocessor have it, regardless of the manufacturer. Systick timer is a part of the core. The dumbest and primitive timer.
- TRNG
  * is described above.
- Unconnected GPIO pins
  * We configure a detached port as an input and then read the value from it. Because of specific physical processes appears noise, which goes with waves, which has minimal statistical dependence.
### Why do I see an inverted skycoin logo in bootloader?

If you see an inverted skycoin logo in bootloader mode like in the following image, maybe you have either flashed for development or not official device.

![Kiku](images/skycoin_logo_inverted_bootloader.jpg)

### What should I do if something fails?

If you are experiencing any issues:

- Determine if your particular case is mentioned in [troubleshooting section](#troubleshooting) and try to follow the corresponding instructions to fix it.
- Contact the developers via [Skycoin development channel in Telegram](https://t.me/skycoindev).

## Troubleshooting

This section describes quick solutions to some common errors or mistakes.

### What does "Got TypeError when importing the protocol definitions for generator" message mean?

If you are getting this error quite likely your system is configured to run Python version `2.x` by default. This version of Python is not supported. At all times `Python3` is a requirement.

Firstly , confirm that Python 2.x was executed by running the following commands from a terminal window:

```sh
which protoc
protoc --version
python -c 'import google.protobuf; print(google.protobuf.__file__)'
```

If `python2` is part of the output then that's exactly the case so continue with instructions that follow. Otherwise [contact the team](#what-should-i-do-if-something-fails).

In order to force using Python3 set `PYTHON=python3` environment variable while invoking all make targets. For instance if building bootloader binary just once

```sh
make bootloader PYTHON=python3
```

In order to invoke multiple targets export that variable to the glovbal OS environment, e.g. on Unix systems

```sh
export PYTHON=python3
make bootloader
make firmware
make full-firmware
```

For further details see #235 .

