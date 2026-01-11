package main

// Base58 encoding for Skycoin addresses
// Based on Bitcoin's base58check encoding

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode encodes data to base58 string
func base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
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

	// Make a copy of data for in-place division
	input := make([]byte, len(data))
	copy(input, data)

	// Encode
	var result []byte
	for {
		// Check if input is all zeros
		allZero := true
		for _, b := range input {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			break
		}

		// Divide input by 58
		var carry uint32
		for i := 0; i < len(input); i++ {
			carry = carry*256 + uint32(input[i])
			input[i] = byte(carry / 58)
			carry = carry % 58
		}
		result = append(result, base58Alphabet[carry])
	}

	// Add leading '1' for each leading zero byte
	for i := 0; i < leadingZeros; i++ {
		result = append(result, '1')
	}

	// Reverse result
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
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

// base58CheckEncode encodes data with a 4-byte checksum
func base58CheckEncode(data []byte) string {
	// Calculate double SHA256 checksum
	hash1 := sha256Sum(data)
	hash2 := sha256Sum(hash1[:])

	// Append first 4 bytes of checksum
	dataWithChecksum := make([]byte, len(data)+4)
	copy(dataWithChecksum, data)
	copy(dataWithChecksum[len(data):], hash2[:4])

	return base58Encode(dataWithChecksum)
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
