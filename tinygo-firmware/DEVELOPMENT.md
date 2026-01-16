# TinyGo Firmware Development Guide

This document details critical considerations for developing TinyGo code that runs on the STM32F205RG bare-metal target (Cortex-M3). Many standard Go patterns do not work correctly in this environment.

## Build Configuration

The firmware is built with these TinyGo options:
- `-target=./stm32f205.json` - Custom target for STM32F205RG
- `-opt=z` - Optimize for size
- `-gc=leaking` - No garbage collection (memory is never freed)
- `-scheduler=none` - No goroutine scheduler

### Build Commands
```bash
make build        # Release build (no debug screens)
make build-debug  # Debug build with debug screens enabled (-tags debug)
make clean        # Remove build artifacts
```

## Critical: String Handling Issues

**The most important issue**: TinyGo bare-metal with `gc=leaking` has severe problems with string operations. Memory allocated for strings gets corrupted.

### DO NOT USE

1. **String slicing** - `s[a:b]` creates a corrupted string
   ```go
   // BAD - will produce garbage
   address := fullAddress[:16]
   ```

2. **String conversion from byte slice** - `string(data[:])` allocates corrupted memory
   ```go
   // BAD - the returned string will be corrupted
   func decode(data []byte) string {
       return string(data[i : i+length])
   }
   ```

3. **String concatenation** - `s1 + s2` allocates memory
   ```go
   // BAD - result will be corrupted
   result := ""
   for i := 0; i < count; i++ {
       result += words[i] + " "
   }
   ```

4. **for-range over string slices** - May cause issues
   ```go
   // POTENTIALLY BAD
   for _, word := range words {
       if word == target { ... }
   }
   ```

### SAFE PATTERNS

1. **Use fixed byte buffers** - Pre-allocate at package level
   ```go
   var myBuffer [256]byte  // Package-level fixed buffer

   func buildString() string {
       pos := 0
       for i := 0; i < len(data); i++ {
           myBuffer[pos] = data[i]
           pos++
       }
       return string(myBuffer[:pos])  // OK - buffer is static
   }
   ```

2. **Use offset/length instead of substrings**
   ```go
   // Return offset and length instead of a string
   func decodeString(data []byte) (offset int, length int) {
       // ... find the string in data ...
       return i, length  // Don't create string
   }

   // Use offset/length to access characters
   for j := offset; j < offset+length; j++ {
       char := data[j]
   }
   ```

3. **Index-based loops instead of for-range**
   ```go
   // GOOD - use index
   for i := 0; i < len(items); i++ {
       item := items[i]
   }

   // AVOID - may cause issues
   for i, item := range items {
       ...
   }
   ```

4. **Byte-by-byte comparison**
   ```go
   // GOOD - manual byte comparison
   func stringsEqual(a, b string) bool {
       if len(a) != len(b) {
           return false
       }
       for i := 0; i < len(a); i++ {
           if a[i] != b[i] {
               return false
           }
       }
       return true
   }

   // BAD - may cause issues
   if a == b { ... }
   ```

5. **Character-by-character output**
   ```go
   // GOOD - draw characters individually
   for i := 0; i < len(text); i++ {
       oledDrawChar(x, y, text[i])
       x += charWidth
   }

   // POTENTIALLY BAD - uses string slicing internally
   oledDrawString(x, y, text[:16])
   ```

## Memory Allocation

With `gc=leaking`, all allocations are permanent. Avoid:

1. **`make()` calls** - Use fixed-size arrays instead
   ```go
   // BAD - allocates on heap
   data := make([]byte, size)

   // GOOD - use package-level fixed array
   var dataBuffer [256]byte
   data := dataBuffer[:size]
   ```

2. **`append()` calls** - Pre-size arrays
   ```go
   // BAD - may reallocate
   items = append(items, newItem)

   // GOOD - use fixed array with index
   var items [MAX_ITEMS]Item
   var itemCount int
   items[itemCount] = newItem
   itemCount++
   ```

3. **Maps** - Use arrays or linear search
   ```go
   // BAD - maps allocate
   handlers := map[int]func(){}

   // GOOD - use switch or array
   switch msgID {
   case ID_PING:
       handlePing()
   }
   ```

## Protobuf Decoding Pattern

When decoding protobuf messages, return offsets/lengths instead of strings:

```go
// Return offset and length into original buffer
func pbDecodeMyMessage(data []byte) (offset int, length int) {
    i := 0
    for i < len(data) {
        tag := uint32(data[i])
        i++
        // ... parse tag ...

        if fieldNum == 1 && wireType == PB_BYTES {
            length := int(data[i])
            i++
            return i, length  // Return offset and length
        }
    }
    return 0, 0
}

// Usage: work directly with original buffer
offset, length := pbDecodeMyMessage(msgInBuffer[:msgInSize])
for j := 0; j < length; j++ {
    char := msgInBuffer[offset+j]
}
```

## BIP39 Word Handling

The BIP39 wordlist requires special handling:

```go
// BAD - string comparison may fail
func findWord(word string) int {
    for i, w := range bip39Words {
        if w == word {
            return i
        }
    }
    return -1
}

// GOOD - byte-by-byte comparison with index loop
func findWordIndex(word string) int {
    for i := 0; i < 2048; i++ {
        w := bip39Words[i]
        if len(w) != len(word) {
            continue
        }
        match := true
        for j := 0; j < len(word); j++ {
            if w[j] != word[j] {
                match = false
                break
            }
        }
        if match {
            return i
        }
    }
    return -1
}

// BEST - work with offsets into original mnemonic string
func findWordIndexInMnemonic(mnemonic string, offset, length int) int {
    for i := 0; i < 2048; i++ {
        w := bip39Words[i]
        if len(w) != length {
            continue
        }
        match := true
        for j := 0; j < length; j++ {
            if w[j] != mnemonic[offset+j] {
                match = false
                break
            }
        }
        if match {
            return i
        }
    }
    return -1
}
```

## Debug Mode

The firmware supports a debug build flag:

```go
//go:build debug
const DebugMode = true

//go:build !debug
const DebugMode = false
```

Use `if DebugMode { ... }` to wrap debug output. The compiler will eliminate the dead code in release builds.

```go
if DebugMode {
    oledDrawString(0, 0, "Debug info")
    oledRefresh()
    usbDelay(1000000)
}
```

## OLED Display

For displaying dynamic text, use character-by-character drawing:

```go
// Display a string without using string slicing
func displayText(x, y int, text string) {
    for i := 0; i < len(text); i++ {
        x += oledDrawChar(x, y, text[i])
    }
}

// Display from byte buffer
func displayBytes(x, y int, data []byte, length int) {
    for i := 0; i < length; i++ {
        x += oledDrawChar(x, y, data[i])
    }
}
```

## Testing

Use `TEST:` prefix with ping commands to run diagnostic tests. All tests return results in a Success message.

### Basic Tests

```bash
# Simple debug test - returns "ABCD1234"
skyhw cli ping "TEST:DEBUG"

# Literal string return test
skyhw cli ping "TEST:LITERAL"

# Echo first 16 bytes of input as hex
skyhw cli ping "TEST:ECHO"

# Single byte test - returns "A"
skyhw cli ping "TEST:A"

# Three byte test - returns "ABC"
skyhw cli ping "TEST:ABC"
```

### Hash Function Tests

```bash
# SHA256("abc") - expect ba7816bf...
skyhw cli ping "TEST:SHA256"

# RIPEMD160("abc") - expect 8eb208f7...
skyhw cli ping "TEST:RIPEMD"

# Base58 encode test
skyhw cli ping "TEST:B58"
```

### Elliptic Curve Tests

```bash
# Field squaring: 2^2 = 4
skyhw cli ping "TEST:SQR"

# Field multiplication: 3 * 5 = 15
skyhw cli ping "TEST:MUL"

# Field inversion: Inv(1)
skyhw cli ping "TEST:INV"

# Field multiplication benchmark (self-assignment)
skyhw cli ping "TEST:BENCH"

# Get generator point G
skyhw cli ping "TEST:GPOINT"

# Point doubling test (2*G)
skyhw cli ping "TEST:DBL"

# 256 iterations of Double on infinity
skyhw cli ping "TEST:LOOP2"
```

### Public Key Tests

```bash
# Public key from seckey=1 (generator G)
skyhw cli ping "TEST:PUBKEY1"

# Public key from seckey=2
skyhw cli ping "TEST:PUBKEY2"

# ECmultGen with seckey=1
skyhw cli ping "TEST:ECMULT"

# ECmultGen without SetXYZ
skyhw cli ping "TEST:ECM"

# SetXYZ conversion test
skyhw cli ping "TEST:SETXYZ"

# Pubkey decompression test
skyhw cli ping "TEST:DECOMP"

# ECDH multiplication test
skyhw cli ping "TEST:ECDH"
```

### Key Derivation Tests

```bash
# Validate secret key
skyhw cli ping "TEST:VALID"

# Hash-until-valid loop test
skyhw cli ping "TEST:LOOP"

# secp256k1Sum test
skyhw cli ping "TEST:SECP"

# deterministicKeyPairIteratorStep
skyhw cli ping "TEST:STEP1"

# deterministicKeyPairIterator
skyhw cli ping "TEST:DKPI"
```

### Address Tests

```bash
# Address from test mnemonic at index 0
skyhw cli ping "TEST:ADDR"

# Address from seckey=1
skyhw cli ping "TEST:ADDR1"
```

### Mnemonic Tests

```bash
# Mnemonic validation with offset-based approach
skyhw cli ping "TEST:VMNEM"
```

### Low-Level Protocol Tests

```bash
# Raw bytes via msgWrite
skyhw cli ping "TEST:RAW"

# Direct buffer write (bypass msgWrite)
skyhw cli ping "TEST:DIRECT"

# Test Features encoding
skyhw cli ping "TEST:FIXED"
```

## Hex Conversion Pattern

When converting between bytes and hex strings, use fixed buffers:

```go
// Fixed buffer at package level
var hexBuf [256]byte

// Convert bytes to hex - uses fixed buffer
func bytesToHex(data []byte) string {
    const hexChars = "0123456789abcdef"
    if len(data) > 128 {
        return ""  // Max 128 bytes input
    }
    for i := 0; i < len(data); i++ {
        hexBuf[i*2] = hexChars[data[i]>>4]
        hexBuf[i*2+1] = hexChars[data[i]&0x0f]
    }
    return string(hexBuf[:len(data)*2])
}

// Fixed buffer for hex decoding
var hexDecodeBuf [64]byte

// Convert hex to bytes - uses fixed buffer
func hexToBytes(s string) []byte {
    if len(s)%2 != 0 || len(s) > 128 {
        return nil
    }
    resultLen := len(s) / 2
    for i := 0; i < resultLen; i++ {
        // ... decode hex chars ...
        hexDecodeBuf[i] = byte(hi<<4 | lo)
    }
    return hexDecodeBuf[:resultLen]
}
```

## Returning Slices from Fixed Buffers

When returning slices that point into package-level buffers, be aware that:
1. Only one caller can use the result at a time
2. The next call will overwrite the buffer

```go
var resultBuf [64]byte

// Each call overwrites the buffer
func getResult() []byte {
    // fill resultBuf
    return resultBuf[:n]  // Returns slice into fixed buffer
}

// WRONG - second call overwrites first
a := getResult()  // Points to resultBuf
b := getResult()  // Also points to resultBuf, a is now invalid!

// CORRECT - copy if you need to keep the result
a := getResult()
var aCopy [64]byte
copy(aCopy[:], a)  // Make a copy before next call
b := getResult()
```

## Common Pitfalls

1. **Large local arrays cause stack overflow** - Local arrays larger than ~64-128 bytes overflow the limited stack in TinyGo bare-metal mode, causing silent memory corruption. Always use package-level (global) buffers for large arrays:
   ```go
   // BAD - 512 byte local array causes stack overflow
   func badFunc() {
       var buf [512]byte  // Stack overflow - data corruption!
       // ... use buf ...
   }

   // GOOD - package-level buffer
   var globalBuf [512]byte  // Stored in BSS, not on stack

   func goodFunc() {
       // Use globalBuf[:]
   }
   ```

2. **Storing decoded strings** - Strings decoded from protobuf point into `msgInBuffer` which gets overwritten. Copy to fixed buffers.

3. **String literals are OK** - Compile-time string literals work fine:
   ```go
   oledDrawString(0, 0, "Hello")  // OK - literal
   ```

4. **Package-level string vars** - Also OK:
   ```go
   var deviceName = "Skywallet"  // OK - package-level
   ```

5. **Stack strings** - May be corrupted after function returns:
   ```go
   func bad() string {
       var buf [32]byte
       // fill buf
       return string(buf[:])  // BAD - stack may be corrupted
   }
   ```

6. **Long operations** - Call `usbPoll()` periodically to maintain USB connection:
   ```go
   for i := 0; i < longLoop; i++ {
       // ... work ...
       if i % 100 == 0 {
           usbPoll()
       }
   }
   ```

7. **Buffer reuse** - Functions using fixed buffers cannot be called recursively or with overlapping lifetimes:
   ```go
   // BAD - hexToBytes buffer gets overwritten
   hash1 := hexToBytes(hex1)
   hash2 := hexToBytes(hex2)  // hash1 now invalid!
   compare(hash1, hash2)      // Wrong - hash1 was overwritten

   // GOOD - copy or use immediately
   hash1 := hexToBytes(hex1)
   var hash1Copy [32]byte
   copy(hash1Copy[:], hash1)
   hash2 := hexToBytes(hex2)
   compare(hash1Copy[:], hash2)  // Correct
   ```

## File Organization

- `debug_on.go` / `debug_off.go` - Debug mode flag (build tags)
- `bip39.go` - BIP39 wordlist and mnemonic functions
- `handlers.go` - Message handlers and dispatch
- `protobuf.go` - Protobuf encoding/decoding
- `recovery.go` - Device recovery flow
- `transaction.go` - Transaction signing
- `keygen.go` - Key derivation
- `storage.go` - Flash storage
- `oled.go` - OLED display driver
- `usb_device.go` - USB HID implementation
