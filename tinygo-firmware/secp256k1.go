package main

// secp256k1 implementation adapted from github.com/skycoin/skycoin/src/cipher/secp256k1-go
// Modified for TinyGo compatibility (no math/big, no encoding/hex)
//
// TODO: Refactor to use skycoin's secp256k1 directly by:
// 1. Moving TinyGo-incompatible helpers (String, GetBig, SetHex, InvVar) to a separate package
// 2. Creating a thin wrapper package that excludes those helpers
// 3. Using go:build constraints to select TinyGo-compatible code
// This would reduce code duplication and ensure crypto correctness from upstream

// Field represents a field element (256-bit mod p)
// Uses 10 x 26-bit limb encoding
type Field struct {
	n [10]uint32
}

// SetB32 sets field from 32 big-endian bytes
func (fd *Field) SetB32(a []byte) {
	fd.n[0] = 0
	fd.n[1] = 0
	fd.n[2] = 0
	fd.n[3] = 0
	fd.n[4] = 0
	fd.n[5] = 0
	fd.n[6] = 0
	fd.n[7] = 0
	fd.n[8] = 0
	fd.n[9] = 0
	var v uint32
	for i := uint(0); i < 32; i++ {
		for j := uint(0); j < 4; j++ {
			limb := (8*i + 2*j) / 26
			shift := (8*i + 2*j) % 26
			v = (uint32)((a[31-i]>>(2*j))&0x3) << shift
			fd.n[limb] |= v
		}
	}
}

// SetBytes sets field from bytes (up to 32)
func (fd *Field) SetBytes(a []byte) {
	if len(a) > 32 {
		return
	}
	if len(a) == 32 {
		fd.SetB32(a)
	} else {
		var buf [32]byte
		copy(buf[32-len(a):], a)
		fd.SetB32(buf[:])
	}
}

// IsOdd checks if field element is odd
func (fd *Field) IsOdd() bool {
	return (fd.n[0] & 1) != 0
}

// IsZero checks if field element is zero
func (fd *Field) IsZero() bool {
	return (fd.n[0] == 0 && fd.n[1] == 0 && fd.n[2] == 0 && fd.n[3] == 0 && fd.n[4] == 0 &&
		fd.n[5] == 0 && fd.n[6] == 0 && fd.n[7] == 0 && fd.n[8] == 0 && fd.n[9] == 0)
}

// SetInt sets field from uint32
func (fd *Field) SetInt(a uint32) {
	fd.n[0] = a
	fd.n[1] = 0
	fd.n[2] = 0
	fd.n[3] = 0
	fd.n[4] = 0
	fd.n[5] = 0
	fd.n[6] = 0
	fd.n[7] = 0
	fd.n[8] = 0
	fd.n[9] = 0
}

// Normalize reduces the field element modulo p
func (fd *Field) Normalize() {
	c := fd.n[0]
	t0 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[1]
	t1 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[2]
	t2 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[3]
	t3 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[4]
	t4 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[5]
	t5 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[6]
	t6 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[7]
	t7 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[8]
	t8 := c & 0x3FFFFFF
	c = (c >> 26) + fd.n[9]
	t9 := c & 0x03FFFFF
	c >>= 22

	d := c*0x3D1 + t0
	t0 = d & 0x3FFFFFF
	d = (d >> 26) + t1 + c*0x40
	t1 = d & 0x3FFFFFF
	d = (d >> 26) + t2
	t2 = d & 0x3FFFFFF
	d = (d >> 26) + t3
	t3 = d & 0x3FFFFFF
	d = (d >> 26) + t4
	t4 = d & 0x3FFFFFF
	d = (d >> 26) + t5
	t5 = d & 0x3FFFFFF
	d = (d >> 26) + t6
	t6 = d & 0x3FFFFFF
	d = (d >> 26) + t7
	t7 = d & 0x3FFFFFF
	d = (d >> 26) + t8
	t8 = d & 0x3FFFFFF
	d = (d >> 26) + t9
	t9 = d & 0x03FFFFF

	low := (uint64(t1) << 26) | uint64(t0)
	var mask uint64
	if (t9 < 0x03FFFFF) ||
		(t8 < 0x3FFFFFF) ||
		(t7 < 0x3FFFFFF) ||
		(t6 < 0x3FFFFFF) ||
		(t5 < 0x3FFFFFF) ||
		(t4 < 0x3FFFFFF) ||
		(t3 < 0x3FFFFFF) ||
		(t2 < 0x3FFFFFF) ||
		(low < 0xFFFFEFFFFFC2F) {
		mask = 0xFFFFFFFFFFFFFFFF
	}
	t9 &= uint32(mask)
	t8 &= uint32(mask)
	t7 &= uint32(mask)
	t6 &= uint32(mask)
	t5 &= uint32(mask)
	t4 &= uint32(mask)
	t3 &= uint32(mask)
	t2 &= uint32(mask)
	low -= ((mask ^ 0xFFFFFFFFFFFFFFFF) & 0xFFFFEFFFFFC2F)

	fd.n[0] = uint32(low) & 0x3FFFFFF
	fd.n[1] = uint32(low>>26) & 0x3FFFFFF
	fd.n[2] = t2
	fd.n[3] = t3
	fd.n[4] = t4
	fd.n[5] = t5
	fd.n[6] = t6
	fd.n[7] = t7
	fd.n[8] = t8
	fd.n[9] = t9
}

// GetB32 gets 32 big-endian bytes from field
func (fd *Field) GetB32(r []byte) {
	var i, j, c, limb, shift uint32
	for i = 0; i < 32; i++ {
		c = 0
		for j = 0; j < 4; j++ {
			limb = (8*i + 2*j) / 26
			shift = (8*i + 2*j) % 26
			c |= ((fd.n[limb] >> shift) & 0x3) << (2 * j)
		}
		r[31-i] = byte(c)
	}
}

// Equals checks if two field elements are equal
func (fd *Field) Equals(b *Field) bool {
	return (fd.n[0] == b.n[0] && fd.n[1] == b.n[1] && fd.n[2] == b.n[2] && fd.n[3] == b.n[3] && fd.n[4] == b.n[4] &&
		fd.n[5] == b.n[5] && fd.n[6] == b.n[6] && fd.n[7] == b.n[7] && fd.n[8] == b.n[8] && fd.n[9] == b.n[9])
}

// SetAdd adds another field element
func (fd *Field) SetAdd(a *Field) {
	fd.n[0] += a.n[0]
	fd.n[1] += a.n[1]
	fd.n[2] += a.n[2]
	fd.n[3] += a.n[3]
	fd.n[4] += a.n[4]
	fd.n[5] += a.n[5]
	fd.n[6] += a.n[6]
	fd.n[7] += a.n[7]
	fd.n[8] += a.n[8]
	fd.n[9] += a.n[9]
}

// MulInt multiplies by a small integer
func (fd *Field) MulInt(a uint32) {
	fd.n[0] *= a
	fd.n[1] *= a
	fd.n[2] *= a
	fd.n[3] *= a
	fd.n[4] *= a
	fd.n[5] *= a
	fd.n[6] *= a
	fd.n[7] *= a
	fd.n[8] *= a
	fd.n[9] *= a
}

// Negate computes -fd (mod p)
func (fd *Field) Negate(r *Field, m uint32) {
	r.n[0] = 0x3FFFC2F*(m+1) - fd.n[0]
	r.n[1] = 0x3FFFFBF*(m+1) - fd.n[1]
	r.n[2] = 0x3FFFFFF*(m+1) - fd.n[2]
	r.n[3] = 0x3FFFFFF*(m+1) - fd.n[3]
	r.n[4] = 0x3FFFFFF*(m+1) - fd.n[4]
	r.n[5] = 0x3FFFFFF*(m+1) - fd.n[5]
	r.n[6] = 0x3FFFFFF*(m+1) - fd.n[6]
	r.n[7] = 0x3FFFFFF*(m+1) - fd.n[7]
	r.n[8] = 0x3FFFFFF*(m+1) - fd.n[8]
	r.n[9] = 0x03FFFFF*(m+1) - fd.n[9]
}

// Inv computes the modular inverse
func (fd *Field) Inv(r *Field) {
	var x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1 Field
	var j int

	fd.Sqr(&x2)
	x2.Mul(&x2, fd)

	x2.Sqr(&x3)
	x3.Mul(&x3, fd)

	x3.Sqr(&x6)
	x6.Sqr(&x6)
	x6.Sqr(&x6)
	x6.Mul(&x6, &x3)

	x6.Sqr(&x9)
	x9.Sqr(&x9)
	x9.Sqr(&x9)
	x9.Mul(&x9, &x3)

	x9.Sqr(&x11)
	x11.Sqr(&x11)
	x11.Mul(&x11, &x2)

	x11.Sqr(&x22)
	for j = 1; j < 11; j++ {
		x22.Sqr(&x22)
	}
	x22.Mul(&x22, &x11)

	x22.Sqr(&x44)
	for j = 1; j < 22; j++ {
		x44.Sqr(&x44)
	}
	x44.Mul(&x44, &x22)

	x44.Sqr(&x88)
	for j = 1; j < 44; j++ {
		x88.Sqr(&x88)
	}
	x88.Mul(&x88, &x44)

	x88.Sqr(&x176)
	for j = 1; j < 88; j++ {
		x176.Sqr(&x176)
	}
	x176.Mul(&x176, &x88)

	x176.Sqr(&x220)
	for j = 1; j < 44; j++ {
		x220.Sqr(&x220)
	}
	x220.Mul(&x220, &x44)

	x220.Sqr(&x223)
	x223.Sqr(&x223)
	x223.Sqr(&x223)
	x223.Mul(&x223, &x3)

	x223.Sqr(&t1)
	for j = 1; j < 23; j++ {
		t1.Sqr(&t1)
	}
	t1.Mul(&t1, &x22)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Mul(&t1, fd)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Mul(&t1, &x2)
	t1.Sqr(&t1)
	t1.Sqr(&t1)
	t1.Mul(r, fd)
}

// sqrtExp is (p+1)/4 for secp256k1 in big-endian bytes
// p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
// (p+1)/4 = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C
var sqrtExp = [32]byte{
	0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xBF, 0xFF, 0xFF, 0x0C,
}

// Sqrt computes square root using simple binary exponentiation
// sqrt(a) = a^((p+1)/4) for p ≡ 3 (mod 4)
func (fd *Field) Sqrt(r *Field) {
	var result, base, temp Field
	result.SetInt(1)
	base = *fd
	base.Normalize()

	// Binary exponentiation: result = fd^sqrtExp
	for i := 31; i >= 0; i-- {
		for j := 0; j < 8; j++ {
			result.Sqr(&temp)
			temp.Normalize()
			result = temp
			if (sqrtExp[31-i]>>(7-uint(j)))&1 == 1 {
				result.Mul(&temp, &base)
				temp.Normalize()
				result = temp
			}
		}
	}

	*r = result
}

// mulTemp is a fixed intermediate buffer for Mul (reduces stack usage)
var mulTemp [20]uint64

// Mul multiplies two field elements using loop-based convolution
func (fd *Field) Mul(r, b *Field) {
	mulStage1(fd, b)
	mulStage2(r)
}

// mulStage1 computes convolution using loops
func mulStage1(a, b *Field) {
	var temp uint64
	var i, j int

	// Lower half: terms 0-9
	for i = 0; i < 10; i++ {
		for j = 0; j <= i; j++ {
			temp += uint64(a.n[j]) * uint64(b.n[i-j])
		}
		mulTemp[i] = temp & 0x3FFFFFF
		temp >>= 26
	}

	// Upper half: terms 10-18
	for i = 10; i < 19; i++ {
		for j = i - 9; j < 10; j++ {
			temp += uint64(a.n[j]) * uint64(b.n[i-j])
		}
		mulTemp[i] = temp & 0x3FFFFFF
		temp >>= 26
	}
	mulTemp[19] = temp
}

// mulStage2 performs the reduction
func mulStage2(r *Field) {
	var c, d uint64

	c = mulTemp[0] + mulTemp[10]*0x3D10
	mulTemp[0] = c & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[1] + mulTemp[10]*0x400 + mulTemp[11]*0x3D10
	mulTemp[1] = c & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[2] + mulTemp[11]*0x400 + mulTemp[12]*0x3D10
	mulTemp[2] = c & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[3] + mulTemp[12]*0x400 + mulTemp[13]*0x3D10
	r.n[3] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[4] + mulTemp[13]*0x400 + mulTemp[14]*0x3D10
	r.n[4] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[5] + mulTemp[14]*0x400 + mulTemp[15]*0x3D10
	r.n[5] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[6] + mulTemp[15]*0x400 + mulTemp[16]*0x3D10
	r.n[6] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[7] + mulTemp[16]*0x400 + mulTemp[17]*0x3D10
	r.n[7] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[8] + mulTemp[17]*0x400 + mulTemp[18]*0x3D10
	r.n[8] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + mulTemp[9] + mulTemp[18]*0x400 + mulTemp[19]*0x1000003D10
	r.n[9] = uint32(c) & 0x03FFFFF
	c = c >> 22
	d = mulTemp[0] + c*0x3D1
	r.n[0] = uint32(d) & 0x3FFFFFF
	d = d >> 26
	d = d + mulTemp[1] + c*0x40
	r.n[1] = uint32(d) & 0x3FFFFFF
	d = d >> 26
	r.n[2] = uint32(mulTemp[2] + d)
}

// sqrTemp is a fixed intermediate buffer for Sqr (reduces stack usage)
var sqrTemp [20]uint64

// Sqr squares a field element
// Split into stages to reduce stack pressure for TinyGo
func (fd *Field) Sqr(r *Field) {
	sqrStage1(fd)
	sqrStage2(r)
}

// sqrStage1 computes the convolution using loops (smaller code)
func sqrStage1(fd *Field) {
	var temp uint64
	var i, j int

	// Lower half: terms 0-9
	for i = 0; i < 10; i++ {
		for j = 0; j <= i; j++ {
			k := i - j
			prod := uint64(fd.n[j]) * uint64(fd.n[k])
			if j == k {
				temp += prod
			} else if j < k {
				temp += prod << 1 // 2 * product for off-diagonal
			}
		}
		sqrTemp[i] = temp & 0x3FFFFFF
		temp >>= 26
	}

	// Upper half: terms 10-18
	for i = 10; i < 19; i++ {
		for j = i - 9; j < 10 && j <= i-j; j++ {
			k := i - j
			if k >= 10 {
				continue
			}
			prod := uint64(fd.n[j]) * uint64(fd.n[k])
			if j == k {
				temp += prod
			} else {
				temp += prod << 1
			}
		}
		sqrTemp[i] = temp & 0x3FFFFFF
		temp >>= 26
	}
	sqrTemp[19] = temp
}

// sqrStage2 performs the reduction
func sqrStage2(r *Field) {
	var c, d uint64

	c = sqrTemp[0] + sqrTemp[10]*0x3D10
	sqrTemp[0] = c & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[1] + sqrTemp[10]*0x400 + sqrTemp[11]*0x3D10
	sqrTemp[1] = c & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[2] + sqrTemp[11]*0x400 + sqrTemp[12]*0x3D10
	sqrTemp[2] = c & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[3] + sqrTemp[12]*0x400 + sqrTemp[13]*0x3D10
	r.n[3] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[4] + sqrTemp[13]*0x400 + sqrTemp[14]*0x3D10
	r.n[4] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[5] + sqrTemp[14]*0x400 + sqrTemp[15]*0x3D10
	r.n[5] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[6] + sqrTemp[15]*0x400 + sqrTemp[16]*0x3D10
	r.n[6] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[7] + sqrTemp[16]*0x400 + sqrTemp[17]*0x3D10
	r.n[7] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[8] + sqrTemp[17]*0x400 + sqrTemp[18]*0x3D10
	r.n[8] = uint32(c) & 0x3FFFFFF
	c = c >> 26
	c = c + sqrTemp[9] + sqrTemp[18]*0x400 + sqrTemp[19]*0x1000003D10
	r.n[9] = uint32(c) & 0x03FFFFF
	c = c >> 22
	d = sqrTemp[0] + c*0x3D1
	r.n[0] = uint32(d) & 0x3FFFFFF
	d = d >> 26
	d = d + sqrTemp[1] + c*0x40
	r.n[1] = uint32(d) & 0x3FFFFFF
	d = d >> 26
	r.n[2] = uint32(sqrTemp[2] + d)
}
