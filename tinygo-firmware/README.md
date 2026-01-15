# Skycoin Hardware Wallet - TinyGo Firmware

This is a TinyGo implementation of the Skycoin hardware wallet firmware for the STM32F205RG microcontroller. It provides the same functionality as the C firmware but written entirely in Go.

## Features

- BIP39 mnemonic generation and validation (12/24 words)
- Skycoin address derivation using deterministic key generation
- ECDSA message signing (secp256k1)
- Transaction signing
- PIN protection
- OLED display (SSD1306, 128x64)
- USB HID communication

## Requirements

### TinyGo

Install TinyGo 0.30.0 or later:

```bash
# On Linux (Ubuntu/Debian)
wget https://github.com/tinygo-org/tinygo/releases/download/v0.30.0/tinygo_0.30.0_amd64.deb
sudo dpkg -i tinygo_0.30.0_amd64.deb

# on Arch Linux (btw)
yay -S tinygo-bin

# On macOS
brew tap tinygo-org/tools
brew install tinygo
```

### ARM Toolchain

The ARM toolchain is needed for linking:

```bash
# On Linux (Ubuntu/Debian)
sudo apt-get install gcc-arm-none-eabi

# on Arch Linux (btw)
sudo pacman -S tinygo-bin gcc-arm-none-eabi


# On macOS
brew tap ArmMbed/homebrew-formulae
brew install arm-none-eabi-gcc
```

### USB Rules (Linux)

Create `/etc/udev/rules.d/99-skywallet.rules`:

```
# Skycoin Hardware Wallet
SUBSYSTEM=="usb", ATTR{idVendor}=="313a", ATTR{idProduct}=="0001", MODE="0666"
KERNEL=="hidraw*", ATTRS{idVendor}=="313a", ATTRS{idProduct}=="0001", MODE="0666"
```

Then reload rules:

```bash
sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Building

### Release Build

```bash
make build
```

This creates `skyfirmware-tinygo.bin` (approximately 71KB).

### Debug Build

```bash
make build-debug
```

Debug builds include additional debug screens for development.

### Clean

```bash
make clean
```

## Flashing

### Via Hardware Wallet Daemon

If the device already has a bootloader installed:

```bash
curl -X PUT http://127.0.0.1:9510/api/v1/firmware_update \
  -F "file=@skyfirmware-tinygo.bin"
```

### Via ST-LINK

For a fresh device or to flash with bootloader:

```bash
# Check device is detected
st-info --probe

# Flash full firmware (bootloader + firmware)
st-flash write full-firmware.bin 0x08000000
```

## Communication

Use the [hardware-wallet-go](https://github.com/skycoin/hardware-wallet-go) library or CLI:

```bash
# Get device features
skyhw cli features

# Ping the device
skyhw cli ping "hello"

# Generate addresses
skyhw cli addressGen --addressN 5

# Sign a message
skyhw cli signMessage --message "test message" --addressN 0
```

## Supported Messages

| Message | Description |
|---------|-------------|
| Initialize | Start session, get Features |
| GetFeatures | Get device information |
| Ping | Echo test, supports TEST: commands |
| Wipe | Factory reset device |
| GenerateMnemonic | Create new 12/24 word mnemonic |
| RecoveryDevice | Restore from existing mnemonic |
| LoadDevice | Load mnemonic directly (debug) |
| SetMnemonic | Set mnemonic with validation |
| ChangePin | Set or change PIN |
| SkycoinAddress | Generate Skycoin addresses |
| SkycoinSignMessage | Sign message with private key |
| TransactionSign | Sign Skycoin transaction |
| GetRawEntropy | Get random bytes |
| GetMixedEntropy | Get entropy mixed with host |
| ApplySettings | Set device label/language |
| Backup | Display mnemonic for backup |
| Cancel | Cancel current operation |

## USB Protocol

- VID: 0x313A, PID: 0x0001
- HID device with 64-byte vendor-defined reports
- Message format: `?##` + msg_id (2B) + length (4B) + protobuf payload
- Multi-packet messages supported (continuation starts with `?`)

## Architecture

```
tinygo-firmware/
├── main.go              # Entry point, main loop
├── usb_device.go        # USB HID state machine
├── usb_descriptors.go   # USB descriptors
├── messages.go          # Message framing protocol
├── protobuf.go          # Protobuf encoding/decoding
├── handlers.go          # Message handlers
├── dispatch.go          # Message dispatcher
├── storage.go           # Flash storage
├── oled.go              # OLED display driver
├── buttons.go           # Button handling, UI layouts
├── bip39.go             # BIP39 mnemonic implementation
├── bip39_words.go       # BIP39 wordlist
├── keygen.go            # Key derivation
├── ecdsa.go             # ECDSA signing
├── secp256k1.go         # secp256k1 field/point math
├── sha256.go            # SHA256 implementation
├── ripemd160.go         # RIPEMD160 implementation
├── base58.go            # Base58 encoding
├── transaction.go       # Transaction signing
├── recovery.go          # Device recovery flow
├── debug_on.go          # Debug mode (build tag)
├── debug_off.go         # Release mode (build tag)
├── stm32f205.json       # TinyGo target definition
├── stm32f205-firmware.ld # Linker script
├── device_stm32f205.s   # Startup assembly
└── Makefile             # Build system
```

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development guidelines, including:

- TinyGo bare-metal memory constraints
- String handling issues with `gc=leaking`
- Fixed buffer patterns
- Protobuf encoding patterns
- Test commands via ping

### Quick Test Commands

```bash
# Test SHA256 implementation
skyhw cli ping "TEST:SHA256"

# Test address generation
skyhw cli ping "TEST:ADDR"

# Test mnemonic validation
skyhw cli ping "TEST:VMNEM"

# Test ECDSA public key generation
skyhw cli ping "TEST:PUBKEY1"
```

See DEVELOPMENT.md for the complete list of TEST: commands.

## Memory Constraints

The firmware runs with:
- `-gc=leaking` - No garbage collection
- `-scheduler=none` - No goroutine scheduler
- `-opt=z` - Size optimization

All memory is statically allocated using fixed-size buffers. Dynamic allocation (`make`, `append`) is avoided to prevent memory corruption.

## Firmware Size

Current binary size: ~71KB (signed)
