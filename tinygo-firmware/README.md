# TinyGo Firmware for Skywallet

TinyGo implementation of the Skywallet firmware for STM32F205RG.

## Status

- USB HID device enumeration with proper descriptors
- Message protocol implementation (framing, multi-packet support)
- Protobuf encoding/decoding for basic messages
- Implemented commands: Initialize, GetFeatures, Ping
- OLED display support

## Build

```bash
make clean
make build
```

## Flash

```bash
curl -X PUT http://127.0.0.1:9510/api/v1/firmware_update -F "file=@skyfirmware-tinygo.bin"
```

## Test

```bash
# Check USB enumeration
lsusb | grep 313a

# Test GetFeatures
skyhw cli features

# Test Ping
skyhw cli ping --message "Hello TinyGo"
```

## Size

```
text    data     bss     dec     hex filename
5688    1812  129264  136764  2163c skyfirmware-tinygo.elf
```

- Binary size: ~7.6KB (signed)
- Code: 5.6KB
- BSS: ~126KB (message buffers, OLED framebuffer)

## Architecture

```
tinygo-firmware/
├── main.go              # Main loop, GPIO, LED
├── oled.go              # SSD1306 OLED driver
├── usb_descriptors.go   # USB device/config/HID descriptors
├── usb_device.go        # USB state machine, EP0/EP1 handling
├── messages.go          # Message framing (64-byte packets)
├── protobuf.go          # Minimal protobuf encoding/decoding
├── dispatch.go          # Message dispatcher
├── handlers.go          # Command handlers
├── types.go             # Message type definitions
├── stm32f205.json       # TinyGo target config
├── stm32f205-firmware.ld # Linker script
└── Makefile             # Build system
```

## USB Protocol

- VID: 0x313A, PID: 0x0001
- HID device with 64-byte vendor-defined reports
- Message format: `?##` + msg_id (2B) + length (4B) + protobuf payload
- Multi-packet messages supported (continuation starts with `?`)

## TODO

- [ ] Storage system (flash memory for mnemonic, PIN)
- [ ] Button input handling
- [ ] PIN protection
- [ ] Passphrase support
- [ ] Skycoin address generation (using github.com/skycoin/skycoin libs)
- [ ] Message signing
- [ ] Transaction signing
