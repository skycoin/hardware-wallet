package main

// RIPEMD160 implementation for Skycoin address generation
// Based on RIPEMD-160 specification

const (
	ripemd160BlockSize = 64
	ripemd160Size      = 20
)

type ripemd160State struct {
	h      [5]uint32
	block  [64]byte
	len    uint64
	bufLen int
}

// Initial hash values
func ripemd160Init(s *ripemd160State) {
	s.h[0] = 0x67452301
	s.h[1] = 0xEFCDAB89
	s.h[2] = 0x98BADCFE
	s.h[3] = 0x10325476
	s.h[4] = 0xC3D2E1F0
	s.len = 0
	s.bufLen = 0
}

// Rotate left
func ripemd160Rotl(x uint32, n uint) uint32 {
	return (x << n) | (x >> (32 - n))
}

// Round functions
func ripemd160F(j int, x, y, z uint32) uint32 {
	switch {
	case j < 16:
		return x ^ y ^ z
	case j < 32:
		return (x & y) | (^x & z)
	case j < 48:
		return (x | ^y) ^ z
	case j < 64:
		return (x & z) | (y & ^z)
	default:
		return x ^ (y | ^z)
	}
}

// K constants for left rounds
func ripemd160KL(j int) uint32 {
	switch {
	case j < 16:
		return 0x00000000
	case j < 32:
		return 0x5A827999
	case j < 48:
		return 0x6ED9EBA1
	case j < 64:
		return 0x8F1BBCDC
	default:
		return 0xA953FD4E
	}
}

// K constants for right rounds
func ripemd160KR(j int) uint32 {
	switch {
	case j < 16:
		return 0x50A28BE6
	case j < 32:
		return 0x5C4DD124
	case j < 48:
		return 0x6D703EF3
	case j < 64:
		return 0x7A6D76E9
	default:
		return 0x00000000
	}
}

// Message word selection for left rounds
var ripemd160RL = [80]int{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
	3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
	1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
	4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
}

// Message word selection for right rounds
var ripemd160RR = [80]int{
	5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
	6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
	15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
	8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
	12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
}

// Rotation amounts for left rounds
var ripemd160SL = [80]uint{
	11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
	7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
	11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
	11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
	9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
}

// Rotation amounts for right rounds
var ripemd160SR = [80]uint{
	8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
	9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
	9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
	15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
	8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
}

func ripemd160Block(s *ripemd160State, data []byte) {
	var w [16]uint32

	// Parse block into 16 32-bit little-endian words
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = uint32(data[j]) | uint32(data[j+1])<<8 | uint32(data[j+2])<<16 | uint32(data[j+3])<<24
	}

	// Initialize working variables
	al, bl, cl, dl, el := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4]
	ar, br, cr, dr, er := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4]

	// 80 rounds
	for j := 0; j < 80; j++ {
		// Left round
		fl := ripemd160F(j, bl, cl, dl)
		tl := al + fl + w[ripemd160RL[j]] + ripemd160KL(j)
		tl = ripemd160Rotl(tl, ripemd160SL[j]) + el
		al = el
		el = dl
		dl = ripemd160Rotl(cl, 10)
		cl = bl
		bl = tl

		// Right round
		fr := ripemd160F(79-j, br, cr, dr)
		tr := ar + fr + w[ripemd160RR[j]] + ripemd160KR(j)
		tr = ripemd160Rotl(tr, ripemd160SR[j]) + er
		ar = er
		er = dr
		dr = ripemd160Rotl(cr, 10)
		cr = br
		br = tr
	}

	// Final addition
	t := s.h[1] + cl + dr
	s.h[1] = s.h[2] + dl + er
	s.h[2] = s.h[3] + el + ar
	s.h[3] = s.h[4] + al + br
	s.h[4] = s.h[0] + bl + cr
	s.h[0] = t
}

func ripemd160Update(s *ripemd160State, data []byte) {
	s.len += uint64(len(data))

	if s.bufLen > 0 {
		n := copy(s.block[s.bufLen:], data)
		s.bufLen += n
		data = data[n:]

		if s.bufLen == ripemd160BlockSize {
			ripemd160Block(s, s.block[:])
			s.bufLen = 0
		}
	}

	for len(data) >= ripemd160BlockSize {
		ripemd160Block(s, data[:ripemd160BlockSize])
		data = data[ripemd160BlockSize:]
	}

	if len(data) > 0 {
		s.bufLen = copy(s.block[:], data)
	}
}

func ripemd160Final(s *ripemd160State, out []byte) {
	tmp := s.block[:]
	tmp[s.bufLen] = 0x80
	s.bufLen++

	if s.bufLen > 56 {
		for i := s.bufLen; i < ripemd160BlockSize; i++ {
			tmp[i] = 0
		}
		ripemd160Block(s, tmp)
		s.bufLen = 0
	}

	for i := s.bufLen; i < 56; i++ {
		tmp[i] = 0
	}

	// Append length in bits (little-endian)
	bitLen := s.len * 8
	tmp[56] = byte(bitLen)
	tmp[57] = byte(bitLen >> 8)
	tmp[58] = byte(bitLen >> 16)
	tmp[59] = byte(bitLen >> 24)
	tmp[60] = byte(bitLen >> 32)
	tmp[61] = byte(bitLen >> 40)
	tmp[62] = byte(bitLen >> 48)
	tmp[63] = byte(bitLen >> 56)

	ripemd160Block(s, tmp)

	// Output hash (little-endian)
	for i := 0; i < 5; i++ {
		out[i*4] = byte(s.h[i])
		out[i*4+1] = byte(s.h[i] >> 8)
		out[i*4+2] = byte(s.h[i] >> 16)
		out[i*4+3] = byte(s.h[i] >> 24)
	}
}

// ripemd160Sum computes RIPEMD160 hash of data
func ripemd160Sum(data []byte) [20]byte {
	var s ripemd160State
	var out [20]byte
	ripemd160Init(&s)
	ripemd160Update(&s, data)
	ripemd160Final(&s, out[:])
	return out
}

// hash160 computes RIPEMD160(SHA256(data)) - used for addresses
func hash160(data []byte) [20]byte {
	sha := sha256Sum(data)
	return ripemd160Sum(sha[:])
}
