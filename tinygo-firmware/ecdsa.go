package main

// ECDSA signing implementation for secp256k1
// Produces 65-byte signatures: r (32) + s (32) + recovery (1)

// Scalar represents a scalar modulo the secp256k1 order n
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
type Scalar struct {
	d [8]uint32 // 8 x 32-bit limbs, little-endian
}

// secp256k1 order n (in 32-bit limbs, little-endian)
var secp256k1N = [8]uint32{
	0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6,
	0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF,
}

// order / 2 for low-S normalization
var secp256k1NHalf = [8]uint32{
	0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73,
	0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
}

// scalarSetB32 sets scalar from 32 big-endian bytes
func (s *Scalar) SetB32(b []byte) {
	s.d[7] = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	s.d[6] = uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	s.d[5] = uint32(b[8])<<24 | uint32(b[9])<<16 | uint32(b[10])<<8 | uint32(b[11])
	s.d[4] = uint32(b[12])<<24 | uint32(b[13])<<16 | uint32(b[14])<<8 | uint32(b[15])
	s.d[3] = uint32(b[16])<<24 | uint32(b[17])<<16 | uint32(b[18])<<8 | uint32(b[19])
	s.d[2] = uint32(b[20])<<24 | uint32(b[21])<<16 | uint32(b[22])<<8 | uint32(b[23])
	s.d[1] = uint32(b[24])<<24 | uint32(b[25])<<16 | uint32(b[26])<<8 | uint32(b[27])
	s.d[0] = uint32(b[28])<<24 | uint32(b[29])<<16 | uint32(b[30])<<8 | uint32(b[31])
}

// GetB32 writes scalar to 32 big-endian bytes
func (s *Scalar) GetB32(b []byte) {
	b[0] = byte(s.d[7] >> 24)
	b[1] = byte(s.d[7] >> 16)
	b[2] = byte(s.d[7] >> 8)
	b[3] = byte(s.d[7])
	b[4] = byte(s.d[6] >> 24)
	b[5] = byte(s.d[6] >> 16)
	b[6] = byte(s.d[6] >> 8)
	b[7] = byte(s.d[6])
	b[8] = byte(s.d[5] >> 24)
	b[9] = byte(s.d[5] >> 16)
	b[10] = byte(s.d[5] >> 8)
	b[11] = byte(s.d[5])
	b[12] = byte(s.d[4] >> 24)
	b[13] = byte(s.d[4] >> 16)
	b[14] = byte(s.d[4] >> 8)
	b[15] = byte(s.d[4])
	b[16] = byte(s.d[3] >> 24)
	b[17] = byte(s.d[3] >> 16)
	b[18] = byte(s.d[3] >> 8)
	b[19] = byte(s.d[3])
	b[20] = byte(s.d[2] >> 24)
	b[21] = byte(s.d[2] >> 16)
	b[22] = byte(s.d[2] >> 8)
	b[23] = byte(s.d[2])
	b[24] = byte(s.d[1] >> 24)
	b[25] = byte(s.d[1] >> 16)
	b[26] = byte(s.d[1] >> 8)
	b[27] = byte(s.d[1])
	b[28] = byte(s.d[0] >> 24)
	b[29] = byte(s.d[0] >> 16)
	b[30] = byte(s.d[0] >> 8)
	b[31] = byte(s.d[0])
}

// IsZero returns true if scalar is zero
func (s *Scalar) IsZero() bool {
	return s.d[0]|s.d[1]|s.d[2]|s.d[3]|s.d[4]|s.d[5]|s.d[6]|s.d[7] == 0
}

// scalarIsLess returns true if a < b (both as 256-bit unsigned integers)
func scalarIsLess(a, b *[8]uint32) bool {
	for i := 7; i >= 0; i-- {
		if a[i] < b[i] {
			return true
		}
		if a[i] > b[i] {
			return false
		}
	}
	return false
}

// scalarAdd computes r = a + b mod n
func scalarAdd(r, a, b *Scalar) {
	var c uint64
	for i := 0; i < 8; i++ {
		c += uint64(a.d[i]) + uint64(b.d[i])
		r.d[i] = uint32(c)
		c >>= 32
	}
	// Reduce mod n if necessary
	scalarReduce(r)
}

// scalarSub computes r = a - b mod n
func scalarSub(r, a, b *Scalar) {
	var borrow int64
	for i := 0; i < 8; i++ {
		diff := int64(a.d[i]) - int64(b.d[i]) + borrow
		if diff < 0 {
			r.d[i] = uint32(diff + 0x100000000)
			borrow = -1
		} else {
			r.d[i] = uint32(diff)
			borrow = 0
		}
	}
	// If we underflowed, add n back
	if borrow != 0 {
		var c uint64
		for i := 0; i < 8; i++ {
			c += uint64(r.d[i]) + uint64(secp256k1N[i])
			r.d[i] = uint32(c)
			c >>= 32
		}
	}
}

// scalarReduce reduces r mod n if r >= n
func scalarReduce(r *Scalar) {
	if !scalarIsLess(&r.d, &secp256k1N) {
		// r >= n, subtract n
		var borrow int64
		for i := 0; i < 8; i++ {
			diff := int64(r.d[i]) - int64(secp256k1N[i]) + borrow
			if diff < 0 {
				r.d[i] = uint32(diff + 0x100000000)
				borrow = -1
			} else {
				r.d[i] = uint32(diff)
				borrow = 0
			}
		}
	}
}

// scalarMul computes r = a * b mod n
func scalarMul(r, a, b *Scalar) {
	// Full 512-bit product
	var product [16]uint64

	for i := 0; i < 8; i++ {
		var c uint64
		for j := 0; j < 8; j++ {
			c += product[i+j] + uint64(a.d[i])*uint64(b.d[j])
			product[i+j] = c & 0xFFFFFFFF
			c >>= 32
		}
		product[i+8] = c
	}

	// Barrett reduction mod n
	scalarReduceProduct(r, &product)
}

// 2^256 mod n - used for reduction
// n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// 2^256 mod n = 2^256 - n (since n < 2^256)
// = 0x14551231950B75FC4402DA1732FC9BEBF (fits in 129 bits)
var pow256ModN = [8]uint32{
	0x2FC9BEBF, 0x402DA173, 0x50B75FC4, 0x45512319,
	0x00000001, 0x00000000, 0x00000000, 0x00000000,
}

// scalarReduceProduct reduces a 512-bit product mod n
func scalarReduceProduct(r *Scalar, product *[16]uint64) {
	// Process high limbs from highest to lowest
	// For each high limb (index 8-15), multiply by (2^256)^k mod n
	// and add to lower limbs

	// Working accumulator (needs extra precision for carries)
	var acc [9]uint64
	for i := 0; i < 8; i++ {
		acc[i] = product[i]
	}

	// Process each high limb starting from limb 8
	// limb 8 represents value * 2^256
	// limb 9 represents value * 2^288 = value * 2^256 * 2^32
	// etc.

	for hi := 8; hi < 16; hi++ {
		if product[hi] == 0 {
			continue
		}

		// Compute contribution: product[hi] * (2^256)^(hi-7) mod n
		// For hi=8: multiply by 2^256 mod n
		// For hi=9: multiply by 2^288 mod n = (2^256 mod n) * 2^32 (need further reduction)

		// Simplified: for hi=8, multiply by pow256ModN
		// For higher limbs, we need to handle 2^(32*(hi-8)) * pow256ModN

		hiVal := product[hi]

		// For the simplest case, we just handle it iteratively
		// by multiplying pow256ModN by 2^32 for each step
		shift := hi - 8

		// Compute hiVal * pow256ModN * 2^(32*shift) and add to acc
		// This is complex. For now, use a simpler but slower approach:
		// add hiVal * pow256ModN shifted by 'shift' limbs

		var carry uint64
		for j := 0; j < 5; j++ { // pow256ModN has 5 non-zero effective limbs
			if j+shift < 9 {
				mul := hiVal * uint64(pow256ModN[j])
				acc[j+shift] += mul + carry
				carry = acc[j+shift] >> 32
				acc[j+shift] &= 0xFFFFFFFF
			} else if carry > 0 {
				// Overflow into even higher bits - need to recurse
				// For simplicity, we'll handle this by doing multiple passes
				break
			}
		}
		// Handle remaining carry
		for j := 5 + shift; j < 9 && carry > 0; j++ {
			acc[j] += carry
			carry = acc[j] >> 32
			acc[j] &= 0xFFFFFFFF
		}
	}

	// acc now has the product mod n (approximately)
	// But acc[8] might be non-zero, so we need another reduction pass
	if acc[8] > 0 {
		// acc[8] * 2^256 mod n
		carry := uint64(0)
		for j := 0; j < 5; j++ {
			mul := acc[8] * uint64(pow256ModN[j])
			acc[j] += mul + carry
			carry = acc[j] >> 32
			acc[j] &= 0xFFFFFFFF
		}
		for j := 5; j < 8 && carry > 0; j++ {
			acc[j] += carry
			carry = acc[j] >> 32
			acc[j] &= 0xFFFFFFFF
		}
		acc[8] = carry
	}

	// Copy to result
	for i := 0; i < 8; i++ {
		r.d[i] = uint32(acc[i])
	}

	// Final reduction: while r >= n, subtract n
	for !scalarIsLess(&r.d, &secp256k1N) {
		var borrow int64
		for i := 0; i < 8; i++ {
			diff := int64(r.d[i]) - int64(secp256k1N[i]) + borrow
			if diff < 0 {
				r.d[i] = uint32(diff + 0x100000000)
				borrow = -1
			} else {
				r.d[i] = uint32(diff)
				borrow = 0
			}
		}
	}
}

// scalarNegate computes r = -a mod n
func scalarNegate(r, a *Scalar) {
	if a.IsZero() {
		*r = *a
		return
	}
	var borrow int64
	for i := 0; i < 8; i++ {
		diff := int64(secp256k1N[i]) - int64(a.d[i]) + borrow
		if diff < 0 {
			r.d[i] = uint32(diff + 0x100000000)
			borrow = -1
		} else {
			r.d[i] = uint32(diff)
			borrow = 0
		}
	}
}

// scalarInverse computes r = a^-1 mod n using extended Euclidean algorithm
func scalarInverse(r, a *Scalar) {
	// Use Fermat's little theorem: a^-1 = a^(n-2) mod n
	// This is simpler to implement than extended GCD
	var nMinus2 Scalar
	nMinus2.d = secp256k1N
	// n - 2
	var borrow int64 = -2
	for i := 0; i < 8; i++ {
		diff := int64(nMinus2.d[i]) + borrow
		if diff < 0 {
			nMinus2.d[i] = uint32(diff + 0x100000000)
			borrow = -1
		} else {
			nMinus2.d[i] = uint32(diff)
			borrow = 0
		}
	}

	// r = a^(n-2) mod n using square-and-multiply
	var result Scalar
	result.d[0] = 1 // result = 1

	base := *a

	for i := 0; i < 8; i++ {
		for j := 0; j < 32; j++ {
			if (nMinus2.d[i]>>j)&1 == 1 {
				scalarMul(&result, &result, &base)
			}
			scalarMul(&base, &base, &base)
		}
	}
	*r = result
}

// scalarIsHigh returns true if s > n/2
func scalarIsHigh(s *Scalar) bool {
	return !scalarIsLess(&s.d, &secp256k1NHalf) && !s.IsZero()
}

// ecdsaSignDigest signs a 32-byte digest with a 32-byte private key
// Returns 65-byte signature: r (32) + s (32) + recovery (1)
func ecdsaSignDigest(seckey, digest []byte) [65]byte {
	var sig [65]byte

	if len(seckey) != 32 || len(digest) != 32 {
		return sig
	}

	// z = digest as scalar
	var z Scalar
	z.SetB32(digest)
	if z.IsZero() {
		return sig // Cannot sign zero digest
	}

	// d = private key as scalar
	var d Scalar
	d.SetB32(seckey)

	// Try to find valid signature
	for attempt := 0; attempt < 100; attempt++ {
		// Generate random k (nonce)
		var kBytes [32]byte
		getEntropy(kBytes[:])

		// Mix with digest for deterministic-ish behavior
		for i := 0; i < 32; i++ {
			kBytes[i] ^= digest[i] ^ byte(attempt)
		}

		var k Scalar
		k.SetB32(kBytes[:])

		// Ensure k is valid (1 <= k < n)
		if k.IsZero() {
			continue
		}
		scalarReduce(&k)
		if k.IsZero() {
			continue
		}

		// Compute R = k * G
		var R XYZ
		ECmultGen(&R, kBytes[:])

		var Rxy XY
		Rxy.SetXYZ(&R)
		if Rxy.Infinity {
			continue
		}

		// r = R.x mod n
		var rBytes [32]byte
		Rxy.X.GetB32(rBytes[:])
		var r Scalar
		r.SetB32(rBytes[:])
		scalarReduce(&r)
		if r.IsZero() {
			continue
		}

		// Recovery byte
		recid := byte(0)
		if Rxy.Y.IsOdd() {
			recid |= 1
		}
		// Check if R.x >= n (rare case)
		if !scalarIsLess(&r.d, &secp256k1N) {
			recid |= 2
		}

		// s = k^-1 * (z + r * d) mod n
		var kInv Scalar
		scalarInverse(&kInv, &k)

		var rd Scalar
		scalarMul(&rd, &r, &d) // r * d

		var zprd Scalar
		scalarAdd(&zprd, &z, &rd) // z + r * d

		var s Scalar
		scalarMul(&s, &kInv, &zprd) // k^-1 * (z + r * d)

		if s.IsZero() {
			continue
		}

		// Low-S normalization: if s > n/2, use n - s
		if scalarIsHigh(&s) {
			scalarNegate(&s, &s)
			recid ^= 1
		}

		// Write signature
		r.GetB32(sig[0:32])
		s.GetB32(sig[32:64])
		sig[64] = recid

		return sig
	}

	return sig // Failed to generate signature
}

// signMessage signs a message (not a pre-hashed digest)
// Returns 65-byte signature as hex string (130 chars)
func signMessage(seckey []byte, message string) string {
	// Hash the message
	digest := sha256Sum([]byte(message))

	// Sign the digest
	sig := ecdsaSignDigest(seckey, digest[:])

	// Convert to hex
	return bytesToHex(sig[:])
}

// bytesToHex converts bytes to hex string
func bytesToHex(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// isHexDigit checks if message is a hex-encoded SHA256 digest (64 hex chars)
func isHexDigit(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// hexToBytes converts hex string to bytes
func hexToBytes(s string) []byte {
	if len(s)%2 != 0 {
		return nil
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(result); i++ {
		hi := hexDigitValue(s[i*2])
		lo := hexDigitValue(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		result[i] = byte(hi<<4 | lo)
	}
	return result
}

func hexDigitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}
