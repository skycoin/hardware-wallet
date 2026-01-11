package main

// Skycoin deterministic key pair generation
// Based on skycoin-api/skycoin_crypto.c

// secp256k1 order for key validation
var secp256k1Order = [32]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
	0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
	0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
}

// seckeyIsValid checks if a secret key is valid
// Must be non-zero and less than the curve order
func seckeyIsValid(seckey []byte) bool {
	if len(seckey) != 32 {
		return false
	}

	// Check if zero
	allZero := true
	for i := 0; i < 32; i++ {
		if seckey[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// Check if less than order (big-endian comparison)
	for i := 0; i < 32; i++ {
		if seckey[i] < secp256k1Order[i] {
			return true
		}
		if seckey[i] > secp256k1Order[i] {
			return false
		}
	}
	// Equal to order - invalid
	return false
}

// deterministicKeyPairIteratorStep generates a keypair from a 32-byte digest
// Keeps hashing until a valid secret key is found
func deterministicKeyPairIteratorStep(digest []byte, seckey, pubkey []byte) bool {
	if len(digest) != 32 || len(seckey) < 32 || len(pubkey) < 33 {
		return false
	}

	// Copy digest to seckey
	copy(seckey[:32], digest)

	// Keep hashing until we get a valid key
	for {
		hash := sha256Sum(seckey[:32])
		copy(seckey[:32], hash[:])

		if seckeyIsValid(seckey[:32]) {
			break
		}
	}

	// Generate public key
	pk := pubkeyFromSeckey(seckey[:32])
	copy(pubkey[:33], pk[:])

	return true
}

// decompressPubkey decompresses a 33-byte compressed public key to XY point
func decompressPubkey(compressed []byte) (xy XY, ok bool) {
	if len(compressed) != 33 {
		return xy, false
	}

	prefix := compressed[0]
	if prefix != 0x02 && prefix != 0x03 {
		return xy, false
	}

	// Set X from bytes
	xy.X.SetBytes(compressed[1:33])

	// Compute y^2 = x^3 + 7
	var x2, x3, y2 Field
	xy.X.Sqr(&x2)
	x2.Mul(&x3, &xy.X)
	var seven Field
	seven.SetInt(7)
	x3.SetAdd(&seven)
	x3.Normalize()
	y2 = x3

	// Compute y = sqrt(y^2) using Tonelli-Shanks for p = 3 mod 4
	// y = y2^((p+1)/4)
	xy.Y.Sqrt(&y2)

	// Check if we need to negate y based on the prefix
	xy.Y.Normalize()
	isOdd := xy.Y.IsOdd()
	needOdd := prefix == 0x03

	if isOdd != needOdd {
		xy.Y.Negate(&xy.Y, 1)
		xy.Y.Normalize()
	}

	xy.Infinity = false

	// Verify the point is on the curve
	if !xy.IsValid() {
		return xy, false
	}

	return xy, true
}

// ecmult computes r = scalar * point using double-and-add
func ecmult(r *XYZ, point *XY, scalar []byte) {
	r.Infinity = true

	// Simple double-and-add
	for i := 0; i < len(scalar); i++ {
		for j := 7; j >= 0; j-- {
			r.Double(r)
			if (scalar[i]>>uint(j))&1 == 1 {
				r.AddXY(r, point)
			}
		}
	}
}

// ecdh performs ECDH: multiply public key by secret key scalar
// Returns compressed public key result
func ecdh(pubkey, seckey []byte) []byte {
	if len(pubkey) != 33 || len(seckey) != 32 {
		return nil
	}

	// Decompress public key to a point
	point, ok := decompressPubkey(pubkey)
	if !ok {
		return nil
	}

	// Multiply point by scalar
	var result XYZ
	ecmult(&result, &point, seckey)

	// Convert to affine coordinates
	var resultXY XY
	resultXY.SetXYZ(&result)

	if resultXY.Infinity {
		return nil
	}

	// Compress the result
	var compressed [33]byte
	var xBytes [32]byte
	resultXY.X.GetB32(xBytes[:])

	if resultXY.Y.IsOdd() {
		compressed[0] = 0x03
	} else {
		compressed[0] = 0x02
	}
	copy(compressed[1:], xBytes[:])

	return compressed[:]
}

// secp256k1Sum computes the Skycoin secp256k1 hash
// This is a special construction used in key derivation
func secp256k1Sum(seed []byte) []byte {
	// hash = SHA256(seed)
	hash := sha256Sum(seed)

	// seckey, pubkey1 = deterministic_key_pair_iterator_step(hash)
	var seckey [32]byte
	var pubkey1 [33]byte
	if !deterministicKeyPairIteratorStep(hash[:], seckey[:], pubkey1[:]) {
		return nil
	}

	// hash2 = SHA256(hash)
	hash2 := sha256Sum(hash[:])

	// _, pubkey2 = deterministic_key_pair_iterator_step(hash2)
	var dummySeckey [32]byte
	var pubkey2 [33]byte
	if !deterministicKeyPairIteratorStep(hash2[:], dummySeckey[:], pubkey2[:]) {
		return nil
	}

	// ecdh_key = ECDH(pubkey2, seckey)
	ecdhKey := ecdh(pubkey2[:], seckey[:])
	if ecdhKey == nil {
		return nil
	}

	// digest = SHA256(hash + ecdh_key)
	combined := make([]byte, 32+33)
	copy(combined[:32], hash[:])
	copy(combined[32:], ecdhKey)
	digest := sha256Sum(combined)

	return digest[:]
}

// deterministicKeyPairIterator generates a keypair and next seed
// Based on Skycoin's DeterministicKeyPairIterator
func deterministicKeyPairIterator(seed []byte, nextSeed, seckey, pubkey []byte) bool {
	if len(nextSeed) < 32 || len(seckey) < 32 || len(pubkey) < 33 {
		return false
	}

	// next_seed = secp256k1sum(seed)
	ns := secp256k1Sum(seed)
	if ns == nil {
		return false
	}
	copy(nextSeed[:32], ns)

	// seed2 = SHA256(seed + next_seed)
	combined := make([]byte, len(seed)+32)
	copy(combined[:len(seed)], seed)
	copy(combined[len(seed):], ns)
	seed2 := sha256Sum(combined)

	// seckey, pubkey = deterministic_key_pair_iterator_step(seed2)
	if !deterministicKeyPairIteratorStep(seed2[:], seckey, pubkey) {
		return false
	}

	return true
}

// deriveKeyPairAtIndex derives the keypair at a specific index from a mnemonic
// index 0 is the first derived key
func deriveKeyPairAtIndex(mnemonic string, index int) (seckey [32]byte, pubkey [33]byte, ok bool) {
	// Convert mnemonic to bytes
	seed := []byte(mnemonic)

	var nextSeed [32]byte
	var sk [32]byte
	var pk [33]byte

	// First iteration uses mnemonic directly
	if !deterministicKeyPairIterator(seed, nextSeed[:], sk[:], pk[:]) {
		return seckey, pubkey, false
	}

	// If index 0, we're done
	if index == 0 {
		copy(seckey[:], sk[:])
		copy(pubkey[:], pk[:])
		return seckey, pubkey, true
	}

	// Iterate to get the key at the desired index
	for i := 1; i <= index; i++ {
		// Use nextSeed as input for next iteration
		seedCopy := make([]byte, 32)
		copy(seedCopy, nextSeed[:])

		if !deterministicKeyPairIterator(seedCopy, nextSeed[:], sk[:], pk[:]) {
			return seckey, pubkey, false
		}
	}

	copy(seckey[:], sk[:])
	copy(pubkey[:], pk[:])
	return seckey, pubkey, true
}

// deriveAddressAtIndex derives the Skycoin address at a specific index
func deriveAddressAtIndex(mnemonic string, index int) string {
	seckey, _, ok := deriveKeyPairAtIndex(mnemonic, index)
	if !ok {
		return ""
	}
	return skycoinAddressFromSeckey(seckey[:])
}

// deriveSecretKeyAtIndex derives just the secret key at a specific index
func deriveSecretKeyAtIndex(mnemonic string, index int) []byte {
	seckey, _, ok := deriveKeyPairAtIndex(mnemonic, index)
	if !ok {
		return nil
	}
	return seckey[:]
}
