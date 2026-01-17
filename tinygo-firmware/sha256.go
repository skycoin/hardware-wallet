package main

// SHA256 implementation for BIP39 checksum
// Based on FIPS 180-4

const (
	sha256BlockSize = 64
	sha256Size      = 32
)

var sha256K = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

type sha256State struct {
	h      [8]uint32
	block  [sha256BlockSize]byte
	len    uint64
	bufLen int
}

func sha256Init(s *sha256State) {
	s.h[0] = 0x6a09e667
	s.h[1] = 0xbb67ae85
	s.h[2] = 0x3c6ef372
	s.h[3] = 0xa54ff53a
	s.h[4] = 0x510e527f
	s.h[5] = 0x9b05688c
	s.h[6] = 0x1f83d9ab
	s.h[7] = 0x5be0cd19
	s.len = 0
	s.bufLen = 0
}

func sha256Rotr(x uint32, n uint) uint32 {
	return (x >> n) | (x << (32 - n))
}

func sha256Block(s *sha256State, data []byte) {
	var w [64]uint32

	// Prepare message schedule
	for i := 0; i < 16; i++ {
		j := i * 4
		w[i] = uint32(data[j])<<24 | uint32(data[j+1])<<16 | uint32(data[j+2])<<8 | uint32(data[j+3])
	}
	for i := 16; i < 64; i++ {
		s0 := sha256Rotr(w[i-15], 7) ^ sha256Rotr(w[i-15], 18) ^ (w[i-15] >> 3)
		s1 := sha256Rotr(w[i-2], 17) ^ sha256Rotr(w[i-2], 19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	// Working variables
	a, b, c, d, e, f, g, h := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7]

	// Compression
	for i := 0; i < 64; i++ {
		S1 := sha256Rotr(e, 6) ^ sha256Rotr(e, 11) ^ sha256Rotr(e, 25)
		ch := (e & f) ^ (^e & g)
		temp1 := h + S1 + ch + sha256K[i] + w[i]
		S0 := sha256Rotr(a, 2) ^ sha256Rotr(a, 13) ^ sha256Rotr(a, 22)
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

func sha256Update(s *sha256State, data []byte) {
	s.len += uint64(len(data))

	// Process any buffered data
	if s.bufLen > 0 {
		n := copy(s.block[s.bufLen:], data)
		s.bufLen += n
		data = data[n:]

		if s.bufLen == sha256BlockSize {
			sha256Block(s, s.block[:])
			s.bufLen = 0
		}
	}

	// Process full blocks
	for len(data) >= sha256BlockSize {
		sha256Block(s, data[:sha256BlockSize])
		data = data[sha256BlockSize:]
	}

	// Buffer remaining
	if len(data) > 0 {
		s.bufLen = copy(s.block[:], data)
	}
}

func sha256Final(s *sha256State, out []byte) {
	// Pad message
	tmp := s.block[:]
	tmp[s.bufLen] = 0x80
	s.bufLen++

	if s.bufLen > 56 {
		// Need extra block
		for i := s.bufLen; i < sha256BlockSize; i++ {
			tmp[i] = 0
		}
		sha256Block(s, tmp)
		s.bufLen = 0
	}

	for i := s.bufLen; i < 56; i++ {
		tmp[i] = 0
	}

	// Append length in bits (big-endian)
	bitLen := s.len * 8
	tmp[56] = byte(bitLen >> 56)
	tmp[57] = byte(bitLen >> 48)
	tmp[58] = byte(bitLen >> 40)
	tmp[59] = byte(bitLen >> 32)
	tmp[60] = byte(bitLen >> 24)
	tmp[61] = byte(bitLen >> 16)
	tmp[62] = byte(bitLen >> 8)
	tmp[63] = byte(bitLen)

	sha256Block(s, tmp)

	// Output hash
	for i := 0; i < 8; i++ {
		out[i*4] = byte(s.h[i] >> 24)
		out[i*4+1] = byte(s.h[i] >> 16)
		out[i*4+2] = byte(s.h[i] >> 8)
		out[i*4+3] = byte(s.h[i])
	}
}

// sha256Sum computes SHA256 hash of data
func sha256Sum(data []byte) [32]byte {
	var s sha256State
	var out [32]byte
	sha256Init(&s)
	sha256Update(&s, data)
	sha256Final(&s, out[:])
	return out
}
