package main

// secp256k1 point operations adapted from github.com/skycoin/skycoin/src/cipher/secp256k1-go
// Modified for TinyGo compatibility

// XY represents a point in affine coordinates
type XY struct {
	X, Y     Field
	Infinity bool
}

// XYZ represents a point in Jacobian coordinates (more efficient for operations)
type XYZ struct {
	X, Y, Z  Field
	Infinity bool
}

// Generator point G
var secp256k1G XY

// Initialize generator point
func init() {
	// G.x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
	secp256k1G.X.SetBytes([]byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	})
	// G.y = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
	secp256k1G.Y.SetBytes([]byte{
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
		0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	})
	secp256k1G.Infinity = false
}

// SetXY sets XYZ from XY (converts affine to Jacobian)
func (xyz *XYZ) SetXY(xy *XY) {
	xyz.Infinity = xy.Infinity
	xyz.X = xy.X
	xyz.Y = xy.Y
	xyz.Z.SetInt(1)
}

// IsValid checks if point is valid
func (xy *XY) IsValid() bool {
	if xy.Infinity {
		return true
	}
	// Check y^2 = x^3 + 7
	var y2, x3 Field
	xy.Y.Sqr(&y2)
	xy.X.Sqr(&x3)
	x3.Mul(&x3, &xy.X)
	var seven Field
	seven.SetInt(7)
	x3.SetAdd(&seven)
	x3.Normalize()
	y2.Normalize()
	return x3.Equals(&y2)
}

// SetXYZ converts XYZ to XY (Jacobian to affine)
func (xy *XY) SetXYZ(xyz *XYZ) {
	if xyz.Infinity {
		xy.Infinity = true
		return
	}
	xy.Infinity = false
	var zi, zi2, zi3 Field
	xyz.Z.Inv(&zi)
	zi.Sqr(&zi2)
	zi2.Mul(&zi3, &zi)
	xyz.X.Mul(&xy.X, &zi2)
	xyz.Y.Mul(&xy.Y, &zi3)
	xy.X.Normalize()
	xy.Y.Normalize()
}

// Double doubles a point in Jacobian coordinates
func (xyz *XYZ) Double(r *XYZ) {
	if xyz.Infinity {
		r.Infinity = true
		return
	}

	var t1, t2, t3, t4, t5 Field

	xyz.Y.Sqr(&t5)
	t5.Mul(&t1, &xyz.X)
	t1.MulInt(4)

	xyz.X.Sqr(&t2)
	t2.MulInt(3)

	t2.Sqr(&r.X)
	t1.Negate(&t3, 1)
	t3.MulInt(2)
	r.X.SetAdd(&t3)

	r.X.Normalize()
	t1.SetAdd(&t3)
	t1.Normalize()
	t1.Negate(&t3, 3)
	r.X.SetAdd(&t3)
	r.X.Normalize()
	t2.Mul(&r.Y, &r.X)
	t5.Sqr(&t3)
	t3.MulInt(8)
	t3.Negate(&t4, 1)
	r.Y.SetAdd(&t4)

	xyz.Y.Mul(&r.Z, &xyz.Z)
	r.Z.MulInt(2)

	r.Infinity = false
}

// AddXY adds an affine point to a Jacobian point
func (xyz *XYZ) AddXY(r *XYZ, xy *XY) {
	if xyz.Infinity {
		r.SetXY(xy)
		return
	}
	if xy.Infinity {
		*r = *xyz
		return
	}

	var z12, u1, u2, s1, s2 Field

	xyz.Z.Sqr(&z12)
	u1 = xyz.X
	z12.Mul(&u2, &xy.X)
	xyz.Z.Mul(&s1, &z12)
	s1.Mul(&s1, &xyz.Y)
	z12.Mul(&s2, &xy.Y)
	u1.Normalize()
	u2.Normalize()

	if u1.Equals(&u2) {
		s1.Normalize()
		s2.Normalize()
		if s1.Equals(&s2) {
			xyz.Double(r)
		} else {
			r.Infinity = true
		}
		return
	}

	var h, i, j, t Field
	u1.Negate(&h, 1)
	h.SetAdd(&u2)
	s1.Negate(&i, 1)
	i.SetAdd(&s2)
	i.MulInt(2)
	h.Sqr(&j)
	j.Mul(&t, &h)
	h.MulInt(2)
	j.Mul(&j, &h)
	u1.Mul(&u1, &t)
	u1.MulInt(2)

	i.Sqr(&r.X)
	r.X.SetAdd(&j)
	j.Negate(&t, 1)
	r.X.SetAdd(&t)
	r.X.SetAdd(&u1)
	r.X.Negate(&t, 1)
	r.X.SetAdd(&t)

	r.X.Normalize()
	u1.MulInt(2)
	u1.SetAdd(&j)
	u1.Negate(&t, 1)
	r.X.SetAdd(&t)
	i.Mul(&r.Y, &r.X)
	s1.Mul(&s1, &j)
	s1.MulInt(2)
	s1.Negate(&t, 1)
	r.Y.SetAdd(&t)

	xyz.Z.Mul(&r.Z, &h)
	r.Infinity = false
}

// ECmultGen computes r = a*G using simple double-and-add
func ECmultGen(r *XYZ, seckey []byte) {
	r.Infinity = true

	var gj XYZ
	gj.SetXY(&secp256k1G)

	// Simple double-and-add (not constant-time, but works)
	for i := 0; i < len(seckey); i++ {
		for j := 7; j >= 0; j-- {
			r.Double(r)
			if (seckey[i]>>uint(j))&1 == 1 {
				r.AddXY(r, &secp256k1G)
			}
		}
	}
}

// pubkeyFromSeckey derives public key from 32-byte secret key
// Returns 33-byte compressed public key
func pubkeyFromSeckey(seckey []byte) [33]byte {
	var result [33]byte

	if len(seckey) != 32 {
		return result
	}

	var xyz XYZ
	ECmultGen(&xyz, seckey)

	var xy XY
	xy.SetXYZ(&xyz)

	if xy.Infinity {
		return result
	}

	// Compressed format: prefix (02/03) + X coordinate
	var xBytes [32]byte
	xy.X.GetB32(xBytes[:])

	if xy.Y.IsOdd() {
		result[0] = 0x03
	} else {
		result[0] = 0x02
	}
	copy(result[1:], xBytes[:])

	return result
}

// skycoinAddressFromPubkey generates a Skycoin address from a compressed public key
func skycoinAddressFromPubkey(pubkey []byte) string {
	if len(pubkey) != 33 {
		return ""
	}

	// Skycoin address = Base58Check(version || RIPEMD160(SHA256(SHA256(pubkey))))
	hash1 := sha256Sum(pubkey)
	hash2 := sha256Sum(hash1[:])
	ripemdHash := ripemd160Sum(hash2[:])

	// Version 0x00 + 20-byte hash
	addrBytes := make([]byte, 21)
	addrBytes[0] = 0x00
	copy(addrBytes[1:], ripemdHash[:])

	return base58CheckEncode(addrBytes)
}

// skycoinAddressFromSeckey generates a Skycoin address from a secret key
func skycoinAddressFromSeckey(seckey []byte) string {
	pubkey := pubkeyFromSeckey(seckey)
	return skycoinAddressFromPubkey(pubkey[:])
}

// deriveKeyFromSeed derives a secret key from a BIP39 seed using simplified BIP32
// path is the derivation path like "m/44'/8000'/0'/0/0"
// For now, returns the first 32 bytes of the seed (simplified)
func deriveKeyFromSeed(seed []byte) []byte {
	// For now, just use HMAC-SHA512 with "Bitcoin seed" as key
	// This gives us the master key
	hmac := hmacSha512([]byte("Bitcoin seed"), seed)
	return hmac[:32] // First 32 bytes is the private key
}
