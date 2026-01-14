package main

// Base58 encoding for Skycoin addresses
// Based on Bitcoin's base58check encoding
// Rewritten to use fixed buffers for TinyGo gc=leaking compatibility

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Fixed buffers for base58 operations (avoids heap allocation)
var (
	base58Input  [64]byte  // Input buffer (max 64 bytes)
	base58Output [64]byte  // Output buffer
	base58Result [64]byte  // Final result
)

// base58EncodeLen holds the length of the last encoded result
var base58EncodeLen int

// base58Encode encodes data to base58, result in base58Result, returns length
func base58Encode(data []byte) string {
	base58EncodeLen = base58EncodeBytes(data)
	if base58EncodeLen == 0 {
		return ""
	}
	return string(base58Result[:base58EncodeLen])
}

// base58EncodeToBytes encodes data to base58, returns byte slice
// Returns slice pointing to base58Result buffer
func base58EncodeToBytes(data []byte) []byte {
	n := base58EncodeBytes(data)
	if n == 0 {
		return nil
	}
	return base58Result[:n]
}

// base58EncodeBytes encodes data to base58 in base58Result buffer
// Returns the length of the encoded string
func base58EncodeBytes(data []byte) int {
	if len(data) == 0 || len(data) > 64 {
		return 0
	}

	// Count leading zeros
	leadingZeros := 0
	for _, b := range data {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	// Copy to fixed input buffer
	inputLen := len(data)
	for i := 0; i < inputLen; i++ {
		base58Input[i] = data[i]
	}

	// Encode
	resultLen := 0
	for {
		// Check if input is all zeros
		allZero := true
		for i := 0; i < inputLen; i++ {
			if base58Input[i] != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			break
		}

		// Divide input by 58
		var carry uint32
		for i := 0; i < inputLen; i++ {
			carry = carry*256 + uint32(base58Input[i])
			base58Input[i] = byte(carry / 58)
			carry = carry % 58
		}
		base58Output[resultLen] = base58Alphabet[carry]
		resultLen++
	}

	// Add leading '1' for each leading zero byte
	for i := 0; i < leadingZeros; i++ {
		base58Output[resultLen] = '1'
		resultLen++
	}

	// Reverse result into final buffer
	for i := 0; i < resultLen; i++ {
		base58Result[i] = base58Output[resultLen-1-i]
	}

	return resultLen
}

// base58Decode decodes a base58 string to bytes
func base58Decode(s string) []byte {
	if len(s) == 0 {
		return nil
	}

	// Count leading '1's
	leadingOnes := 0
	for _, c := range s {
		if c == '1' {
			leadingOnes++
		} else {
			break
		}
	}

	// Decode
	result := make([]byte, 0)
	for _, c := range s {
		// Find character in alphabet
		idx := -1
		for i, ch := range base58Alphabet {
			if byte(c) == base58Alphabet[i] {
				idx = i
				_ = ch
				break
			}
		}
		if idx < 0 {
			return nil // Invalid character
		}

		// Multiply result by 58 and add digit
		carry := idx
		for i := len(result) - 1; i >= 0; i-- {
			carry += int(result[i]) * 58
			result[i] = byte(carry & 0xFF)
			carry >>= 8
		}
		for carry > 0 {
			result = append([]byte{byte(carry & 0xFF)}, result...)
			carry >>= 8
		}
	}

	// Add leading zero bytes
	zeros := make([]byte, leadingOnes)
	return append(zeros, result...)
}

// base58CheckBuffer is used for adding checksum without heap allocation
var base58CheckBuffer [64]byte

// base58CheckEncode encodes data with a 4-byte checksum
func base58CheckEncode(data []byte) string {
	if len(data) > 60 {
		return "" // Max 60 bytes input (+ 4 byte checksum)
	}

	// Calculate double SHA256 checksum
	hash1 := sha256Sum(data)
	hash2 := sha256Sum(hash1[:])

	// Copy data and append first 4 bytes of checksum
	dataLen := len(data)
	for i := 0; i < dataLen; i++ {
		base58CheckBuffer[i] = data[i]
	}
	base58CheckBuffer[dataLen] = hash2[0]
	base58CheckBuffer[dataLen+1] = hash2[1]
	base58CheckBuffer[dataLen+2] = hash2[2]
	base58CheckBuffer[dataLen+3] = hash2[3]

	return base58Encode(base58CheckBuffer[:dataLen+4])
}

// base58CheckEncodeBytes encodes data with a 4-byte checksum, returns bytes
// Result is in base58Result buffer, returns slice pointing to it
func base58CheckEncodeBytes(data []byte) []byte {
	if len(data) > 60 {
		return nil // Max 60 bytes input (+ 4 byte checksum)
	}

	// Calculate double SHA256 checksum
	hash1 := sha256Sum(data)
	hash2 := sha256Sum(hash1[:])

	// Copy data and append first 4 bytes of checksum
	dataLen := len(data)
	for i := 0; i < dataLen; i++ {
		base58CheckBuffer[i] = data[i]
	}
	base58CheckBuffer[dataLen] = hash2[0]
	base58CheckBuffer[dataLen+1] = hash2[1]
	base58CheckBuffer[dataLen+2] = hash2[2]
	base58CheckBuffer[dataLen+3] = hash2[3]

	n := base58EncodeBytes(base58CheckBuffer[:dataLen+4])
	if n == 0 {
		return nil
	}
	return base58Result[:n]
}

// base58CheckDecode decodes base58check string, returns data without checksum
// Returns nil if checksum is invalid
func base58CheckDecode(s string) []byte {
	data := base58Decode(s)
	if len(data) < 5 {
		return nil // Too short
	}

	// Split data and checksum
	payload := data[:len(data)-4]
	checksum := data[len(data)-4:]

	// Verify checksum
	hash1 := sha256Sum(payload)
	hash2 := sha256Sum(hash1[:])

	for i := 0; i < 4; i++ {
		if checksum[i] != hash2[i] {
			return nil // Checksum mismatch
		}
	}

	return payload
}
