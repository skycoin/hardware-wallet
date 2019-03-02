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
  * Yes, when performing cryptographically sensitive operations e.g. mnemonic generation
    if a low internal entropy is detected then an external random 32 bytes 
    buffer is used to increase internal entropy, as long as external buffer have an
    entropy level of at least 4.0 bits/symbol.
- How does the hardware wallet get entropy?
  * The hardware wallet generates internal entropy from a peripheral device and
    eventually combine this with an external entropy received from the user host device.
- How does the hardware wallet ensure having enough entropy to generate a recovery seed?
  * The device builds a histogram with the random buffer as input and measures the
    [Shannon entropy level](ihttps://en.wiktionary.org/wiki/Shannon_entropy) over
    this histogram. A value of at least 4.0 bits/symbol is considered good enough.
