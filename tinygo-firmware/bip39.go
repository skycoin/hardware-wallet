package main

// BIP39 mnemonic generation
// Based on https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

// Mnemonic word counts and their entropy sizes:
// 12 words = 128 bits entropy + 4 bit checksum = 132 bits
// 15 words = 160 bits entropy + 5 bit checksum = 165 bits
// 18 words = 192 bits entropy + 6 bit checksum = 198 bits
// 21 words = 224 bits entropy + 7 bit checksum = 231 bits
// 24 words = 256 bits entropy + 8 bit checksum = 264 bits

const (
	MnemonicWords12 = 12
	MnemonicWords24 = 24
)

// entropyBuffer is a fixed buffer for entropy generation
var entropyBuffer [32]byte

// generateMnemonic generates a BIP39 mnemonic phrase
// wordCount must be 12 or 24
// Returns the mnemonic as a space-separated string
func generateMnemonic(wordCount int) string {
	var entropyBytes int
	switch wordCount {
	case 12:
		entropyBytes = 16 // 128 bits
	case 24:
		entropyBytes = 32 // 256 bits
	default:
		return "" // Invalid word count
	}

	// Generate random entropy using fixed buffer
	getEntropy(entropyBuffer[:entropyBytes])

	return entropyToMnemonic(entropyBuffer[:entropyBytes])
}

// mnemonicBuffer is a fixed buffer for mnemonic generation
// 24 words * max 8 chars per word + 23 spaces = 215 max
var mnemonicBuffer [256]byte

// entropyToMnemonic converts entropy bytes to a mnemonic phrase
func entropyToMnemonic(entropy []byte) string {
	// Calculate checksum (first n bits of SHA256 hash)
	// n = entropy_bits / 32
	hash := sha256Sum(entropy)
	checksumBits := len(entropy) * 8 / 32

	// Combine entropy and checksum into bit string
	// Total bits = entropy_bits + checksum_bits
	totalBits := len(entropy)*8 + checksumBits

	// Extract 11-bit groups to get word indices
	wordCount := totalBits / 11

	// Build result in fixed buffer
	pos := 0

	for i := 0; i < wordCount; i++ {
		// Get 11 bits starting at bit position i*11
		index := getWordIndex(entropy, hash[:], i*11)
		word := bip39Words[index]

		if i > 0 && pos < len(mnemonicBuffer) {
			mnemonicBuffer[pos] = ' '
			pos++
		}
		// Copy word to buffer
		for j := 0; j < len(word) && pos < len(mnemonicBuffer); j++ {
			mnemonicBuffer[pos] = word[j]
			pos++
		}
	}

	return string(mnemonicBuffer[:pos])
}

// entropyToMnemonicBytes writes mnemonic directly to a destination buffer
// Returns the number of bytes written
// This avoids string conversion which causes corruption in TinyGo bare-metal
func entropyToMnemonicBytes(entropy []byte, dest []byte) int {
	// Calculate checksum (first n bits of SHA256 hash)
	// n = entropy_bits / 32
	hash := sha256Sum(entropy)
	checksumBits := len(entropy) * 8 / 32

	// Combine entropy and checksum into bit string
	// Total bits = entropy_bits + checksum_bits
	totalBits := len(entropy)*8 + checksumBits

	// Extract 11-bit groups to get word indices
	wordCount := totalBits / 11

	// Build result directly in destination buffer
	pos := 0

	for i := 0; i < wordCount; i++ {
		// Get 11 bits starting at bit position i*11
		index := getWordIndex(entropy, hash[:], i*11)
		word := bip39Words[index]

		if i > 0 && pos < len(dest) {
			dest[pos] = ' '
			pos++
		}
		// Copy word to buffer
		for j := 0; j < len(word) && pos < len(dest); j++ {
			dest[pos] = word[j]
			pos++
		}
	}

	return pos
}

// getWordIndex extracts 11 bits from entropy+checksum at the given bit offset
func getWordIndex(entropy, checksum []byte, bitOffset int) uint16 {
	entropyBits := len(entropy) * 8
	var index uint16

	for j := 0; j < 11; j++ {
		bitPos := bitOffset + j
		var bit byte

		if bitPos < entropyBits {
			// Bit is in entropy
			byteIdx := bitPos / 8
			bitIdx := 7 - (bitPos % 8) // MSB first
			bit = (entropy[byteIdx] >> bitIdx) & 1
		} else {
			// Bit is in checksum
			checksumPos := bitPos - entropyBits
			byteIdx := checksumPos / 8
			bitIdx := 7 - (checksumPos % 8) // MSB first
			bit = (checksum[byteIdx] >> bitIdx) & 1
		}

		index = (index << 1) | uint16(bit)
	}

	return index
}

// validateMnemonicEntropy is a fixed buffer for validation
var validateMnemonicEntropy [32]byte

// splitMnemonicBytesInto parses a mnemonic byte slice into word offsets/lengths
// Stores results in global arrays to avoid any string/slice allocation
func splitMnemonicBytesInto(mnemonic []byte) int {
	wordIdx := 0
	start := 0
	for i := 0; i <= len(mnemonic); i++ {
		if i == len(mnemonic) || mnemonic[i] == ' ' {
			if i > start && wordIdx < 24 {
				splitMnemonicOffsets[wordIdx] = start
				splitMnemonicLengths[wordIdx] = i - start
				wordIdx++
			}
			start = i + 1
		}
	}
	splitMnemonicCount = wordIdx
	return wordIdx
}

// findWordIndexInMnemonicBytes finds the BIP39 word index for a word in a byte slice
// Uses offset and length to avoid any string operations
func findWordIndexInMnemonicBytes(mnemonic []byte, offset, length int) int {
	// Linear search with manual byte comparison
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

// validateMnemonicBytes checks if a mnemonic byte slice is valid
// Works directly with byte slices to avoid TinyGo string allocation issues
func validateMnemonicBytes(mnemonic []byte) bool {
	// Split into word offsets (no string allocation)
	wordCount := splitMnemonicBytesInto(mnemonic)

	// Check word count
	if wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24 {
		return false
	}

	// Convert words to indices and extract entropy+checksum bits
	entropyBits := wordCount * 11
	checksumBits := entropyBits / 33
	entropyBytes := (entropyBits - checksumBits) / 8

	// Use fixed buffer and clear it
	for i := 0; i < entropyBytes; i++ {
		validateMnemonicEntropy[i] = 0
	}
	var checksumByte byte

	bitPos := 0
	// Process each word using offset/length (no string conversion)
	for wi := 0; wi < wordCount; wi++ {
		// Find word index using offset directly into mnemonic bytes
		idx := findWordIndexInMnemonicBytes(mnemonic, splitMnemonicOffsets[wi], splitMnemonicLengths[wi])
		if idx < 0 {
			return false // Word not found
		}

		// Extract 11 bits from index
		for j := 10; j >= 0; j-- {
			bit := (idx >> j) & 1
			if bitPos < entropyBytes*8 {
				// Store in entropy
				byteIdx := bitPos / 8
				bitIdx := 7 - (bitPos % 8)
				if bit == 1 {
					validateMnemonicEntropy[byteIdx] |= 1 << bitIdx
				}
			} else {
				// Store in checksum
				checksumPos := bitPos - entropyBytes*8
				bitIdx := 7 - checksumPos
				if bit == 1 {
					checksumByte |= 1 << bitIdx
				}
			}
			bitPos++
		}
	}

	// Verify checksum
	hash := sha256Sum(validateMnemonicEntropy[:entropyBytes])
	expectedChecksum := hash[0] >> (8 - checksumBits)
	actualChecksum := checksumByte >> (8 - checksumBits)

	return expectedChecksum == actualChecksum
}

// validateMnemonic checks if a mnemonic phrase is valid
// Uses offset-based word parsing to avoid TinyGo string allocation issues
func validateMnemonic(mnemonic string) bool {
	// Split into word offsets (no string allocation)
	wordCount := splitMnemonicInto(mnemonic)

	// Check word count
	if wordCount != 12 && wordCount != 15 && wordCount != 18 && wordCount != 21 && wordCount != 24 {
		return false
	}

	// Convert words to indices and extract entropy+checksum bits
	entropyBits := wordCount * 11
	checksumBits := entropyBits / 33
	entropyBytes := (entropyBits - checksumBits) / 8

	// Use fixed buffer and clear it
	for i := 0; i < entropyBytes; i++ {
		validateMnemonicEntropy[i] = 0
	}
	var checksumByte byte

	bitPos := 0
	// Process each word using offset/length (no string conversion)
	for wi := 0; wi < wordCount; wi++ {
		// Find word index using offset directly into mnemonic string
		idx := findWordIndexInMnemonic(mnemonic, splitMnemonicOffsets[wi], splitMnemonicLengths[wi])
		if idx < 0 {
			return false // Word not found
		}

		// Extract 11 bits from index
		for j := 10; j >= 0; j-- {
			bit := (idx >> j) & 1
			if bitPos < entropyBytes*8 {
				// Store in entropy
				byteIdx := bitPos / 8
				bitIdx := 7 - (bitPos % 8)
				if bit == 1 {
					validateMnemonicEntropy[byteIdx] |= 1 << bitIdx
				}
			} else {
				// Store in checksum
				checksumPos := bitPos - entropyBytes*8
				bitIdx := 7 - checksumPos
				if bit == 1 {
					checksumByte |= 1 << bitIdx
				}
			}
			bitPos++
		}
	}

	// Verify checksum
	hash := sha256Sum(validateMnemonicEntropy[:entropyBytes])
	expectedChecksum := hash[0] >> (8 - checksumBits)
	actualChecksum := checksumByte >> (8 - checksumBits)

	return expectedChecksum == actualChecksum
}

// splitMnemonicOffsets stores word start positions in the mnemonic
var splitMnemonicOffsets [24]int

// splitMnemonicLengths stores word lengths
var splitMnemonicLengths [24]int

// splitMnemonicCount stores the number of words found
var splitMnemonicCount int

// splitMnemonicInto parses a mnemonic into word offsets/lengths
// Stores results in global arrays to avoid any string/slice allocation
func splitMnemonicInto(mnemonic string) int {
	wordIdx := 0
	start := 0
	for i := 0; i <= len(mnemonic); i++ {
		if i == len(mnemonic) || mnemonic[i] == ' ' {
			if i > start && wordIdx < 24 {
				splitMnemonicOffsets[wordIdx] = start
				splitMnemonicLengths[wordIdx] = i - start
				wordIdx++
			}
			start = i + 1
		}
	}
	splitMnemonicCount = wordIdx
	return wordIdx
}

// findWordIndexInMnemonic finds the BIP39 word index for a word in the mnemonic
// Uses offset and length to avoid any string operations
func findWordIndexInMnemonic(mnemonic string, offset, length int) int {
	// Linear search with manual byte comparison
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

// splitMnemonicWords is kept for compatibility but not used in validation
var splitMnemonicWords [24][9]byte
var splitMnemonicWordLens [24]int
var splitMnemonicResult [24]string

// splitMnemonic splits a mnemonic string into words
// NOTE: This function is kept for compatibility but may have issues in TinyGo bare-metal
// Use splitMnemonicInto + findWordIndexInMnemonic for validation instead
func splitMnemonic(mnemonic string) []string {
	wordIdx := 0
	start := 0
	for i := 0; i <= len(mnemonic); i++ {
		if i == len(mnemonic) || mnemonic[i] == ' ' {
			if i > start && wordIdx < 24 {
				wordLen := i - start
				if wordLen > 8 {
					wordLen = 8
				}
				for j := 0; j < wordLen; j++ {
					splitMnemonicWords[wordIdx][j] = mnemonic[start+j]
				}
				splitMnemonicWordLens[wordIdx] = wordLen
				splitMnemonicResult[wordIdx] = string(splitMnemonicWords[wordIdx][:wordLen])
				wordIdx++
			}
			start = i + 1
		}
	}
	return splitMnemonicResult[:wordIdx]
}

// findWordIndex finds the index of a word in the BIP39 wordlist
// Returns -1 if not found
// Uses byte-by-byte comparison to avoid TinyGo bare-metal string comparison issues
func findWordIndex(word string) int {
	wordLen := len(word)
	// Linear search with manual byte comparison
	for i := 0; i < 2048; i++ {
		w := bip39Words[i]
		if len(w) != wordLen {
			continue
		}
		match := true
		for j := 0; j < wordLen; j++ {
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

// mnemonicToSeed converts a mnemonic to a 512-bit seed using PBKDF2-HMAC-SHA512
// This is the full BIP39 seed derivation
// Fixed buffers for PBKDF2 (avoid make/append)
var pbkdf2SaltBuf [128]byte     // "mnemonic" + passphrase + 4 byte block number
var pbkdf2PasswordBuf [256]byte // mnemonic as bytes

// passphrase is optional (typically empty string)
func mnemonicToSeed(mnemonic, passphrase string) [64]byte {
	// PBKDF2-HMAC-SHA512 with:
	// - password = mnemonic (normalized NFKD, but we skip normalization for ASCII)
	// - salt = "mnemonic" + passphrase
	// - iterations = 2048
	// - dkLen = 64 bytes

	// Copy mnemonic to fixed buffer
	passwordLen := len(mnemonic)
	if passwordLen > 255 {
		passwordLen = 255
	}
	for i := 0; i < passwordLen; i++ {
		pbkdf2PasswordBuf[i] = mnemonic[i]
	}

	// Build salt: "mnemonic" + passphrase
	saltLen := 8 + len(passphrase)
	if saltLen > 124 { // Leave room for block number
		saltLen = 124
	}
	// Copy "mnemonic"
	pbkdf2SaltBuf[0] = 'm'
	pbkdf2SaltBuf[1] = 'n'
	pbkdf2SaltBuf[2] = 'e'
	pbkdf2SaltBuf[3] = 'm'
	pbkdf2SaltBuf[4] = 'o'
	pbkdf2SaltBuf[5] = 'n'
	pbkdf2SaltBuf[6] = 'i'
	pbkdf2SaltBuf[7] = 'c'
	// Copy passphrase
	for i := 0; i < len(passphrase) && i < 116; i++ {
		pbkdf2SaltBuf[8+i] = passphrase[i]
	}

	return pbkdf2Sha512(pbkdf2PasswordBuf[:passwordLen], pbkdf2SaltBuf[:saltLen], 2048, 64)
}

// pbkdf2Sha512 implements PBKDF2 with HMAC-SHA512
// Uses fixed buffer for salt with block number
func pbkdf2Sha512(password, salt []byte, iterations, keyLen int) [64]byte {
	var result [64]byte

	// For 64-byte output, we only need one block (SHA512 produces 64 bytes)
	// U1 = PRF(Password, Salt || INT(1))
	// U2 = PRF(Password, U1)
	// ...
	// DK = U1 ^ U2 ^ ... ^ Uc

	// Copy salt and append block number (1)
	saltLen := len(salt)
	if saltLen > 124 {
		saltLen = 124
	}
	// Salt is already in pbkdf2SaltBuf from caller, just add block number
	pbkdf2SaltBuf[saltLen+0] = 0
	pbkdf2SaltBuf[saltLen+1] = 0
	pbkdf2SaltBuf[saltLen+2] = 0
	pbkdf2SaltBuf[saltLen+3] = 1

	// U1 = HMAC-SHA512(password, salt || 1)
	u := hmacSha512(password, pbkdf2SaltBuf[:saltLen+4])
	copy(result[:], u[:])

	// Iterate
	for i := 1; i < iterations; i++ {
		u = hmacSha512(password, u[:])
		for j := 0; j < 64; j++ {
			result[j] ^= u[j]
		}
	}

	return result
}

// SHA512 constants
var sha512K = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// sha512 initial hash values
var sha512H0 = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

type sha512State struct {
	h      [8]uint64
	block  [128]byte
	len    uint64
	bufLen int
}

func sha512Init(s *sha512State) {
	s.h = sha512H0
	s.len = 0
	s.bufLen = 0
}

func sha512Rotr(x uint64, n uint) uint64 {
	return (x >> n) | (x << (64 - n))
}

func sha512Block(s *sha512State, data []byte) {
	var w [80]uint64

	// Prepare message schedule
	for i := 0; i < 16; i++ {
		j := i * 8
		w[i] = uint64(data[j])<<56 | uint64(data[j+1])<<48 |
			uint64(data[j+2])<<40 | uint64(data[j+3])<<32 |
			uint64(data[j+4])<<24 | uint64(data[j+5])<<16 |
			uint64(data[j+6])<<8 | uint64(data[j+7])
	}
	for i := 16; i < 80; i++ {
		s0 := sha512Rotr(w[i-15], 1) ^ sha512Rotr(w[i-15], 8) ^ (w[i-15] >> 7)
		s1 := sha512Rotr(w[i-2], 19) ^ sha512Rotr(w[i-2], 61) ^ (w[i-2] >> 6)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	a, b, c, d, e, f, g, h := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7]

	for i := 0; i < 80; i++ {
		S1 := sha512Rotr(e, 14) ^ sha512Rotr(e, 18) ^ sha512Rotr(e, 41)
		ch := (e & f) ^ (^e & g)
		temp1 := h + S1 + ch + sha512K[i] + w[i]
		S0 := sha512Rotr(a, 28) ^ sha512Rotr(a, 34) ^ sha512Rotr(a, 39)
		maj := (a & b) ^ (a & c) ^ (b & c)
		temp2 := S0 + maj

		h = g
		g = f
		f = e
		e = d + temp1
		d = c
		c = b
		b = a
		a = temp1 + temp2
	}

	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
	s.h[5] += f
	s.h[6] += g
	s.h[7] += h
}

func sha512Update(s *sha512State, data []byte) {
	s.len += uint64(len(data))

	if s.bufLen > 0 {
		n := copy(s.block[s.bufLen:], data)
		s.bufLen += n
		data = data[n:]

		if s.bufLen == 128 {
			sha512Block(s, s.block[:])
			s.bufLen = 0
		}
	}

	for len(data) >= 128 {
		sha512Block(s, data[:128])
		data = data[128:]
	}

	if len(data) > 0 {
		s.bufLen = copy(s.block[:], data)
	}
}

func sha512Final(s *sha512State, out []byte) {
	tmp := s.block[:]
	tmp[s.bufLen] = 0x80
	s.bufLen++

	if s.bufLen > 112 {
		for i := s.bufLen; i < 128; i++ {
			tmp[i] = 0
		}
		sha512Block(s, tmp)
		s.bufLen = 0
	}

	for i := s.bufLen; i < 112; i++ {
		tmp[i] = 0
	}

	// Append length in bits (128-bit, but we only use lower 64 bits)
	bitLen := s.len * 8
	tmp[112] = 0
	tmp[113] = 0
	tmp[114] = 0
	tmp[115] = 0
	tmp[116] = 0
	tmp[117] = 0
	tmp[118] = 0
	tmp[119] = 0
	tmp[120] = byte(bitLen >> 56)
	tmp[121] = byte(bitLen >> 48)
	tmp[122] = byte(bitLen >> 40)
	tmp[123] = byte(bitLen >> 32)
	tmp[124] = byte(bitLen >> 24)
	tmp[125] = byte(bitLen >> 16)
	tmp[126] = byte(bitLen >> 8)
	tmp[127] = byte(bitLen)

	sha512Block(s, tmp)

	for i := 0; i < 8; i++ {
		out[i*8] = byte(s.h[i] >> 56)
		out[i*8+1] = byte(s.h[i] >> 48)
		out[i*8+2] = byte(s.h[i] >> 40)
		out[i*8+3] = byte(s.h[i] >> 32)
		out[i*8+4] = byte(s.h[i] >> 24)
		out[i*8+5] = byte(s.h[i] >> 16)
		out[i*8+6] = byte(s.h[i] >> 8)
		out[i*8+7] = byte(s.h[i])
	}
}

func sha512Sum(data []byte) [64]byte {
	var s sha512State
	var out [64]byte
	sha512Init(&s)
	sha512Update(&s, data)
	sha512Final(&s, out[:])
	return out
}

// Global buffers for HMAC-SHA512 to avoid stack overflow
// (3 x 128 = 384 bytes is too large for stack in TinyGo bare-metal)
var hmacKeyBuf [128]byte
var hmacIpadBuf [128]byte
var hmacOpadBuf [128]byte

// hmacSha512 computes HMAC-SHA512
func hmacSha512(key, message []byte) [64]byte {
	const blockSize = 128

	// Clear buffers first
	for i := 0; i < 128; i++ {
		hmacKeyBuf[i] = 0
	}

	// If key is longer than block size, hash it
	if len(key) > blockSize {
		hash := sha512Sum(key)
		copy(hmacKeyBuf[:], hash[:])
	} else {
		copy(hmacKeyBuf[:], key)
	}

	// Pad key to block size (already zero-padded)

	// Inner padding
	for i := 0; i < 128; i++ {
		hmacIpadBuf[i] = hmacKeyBuf[i] ^ 0x36
	}

	// Outer padding
	for i := 0; i < 128; i++ {
		hmacOpadBuf[i] = hmacKeyBuf[i] ^ 0x5c
	}

	// Inner hash: SHA512(ipad || message)
	var innerState sha512State
	sha512Init(&innerState)
	sha512Update(&innerState, hmacIpadBuf[:])
	sha512Update(&innerState, message)
	var innerHash [64]byte
	sha512Final(&innerState, innerHash[:])

	// Outer hash: SHA512(opad || inner_hash)
	var outerState sha512State
	sha512Init(&outerState)
	sha512Update(&outerState, hmacOpadBuf[:])
	sha512Update(&outerState, innerHash[:])
	var result [64]byte
	sha512Final(&outerState, result[:])

	return result
}
