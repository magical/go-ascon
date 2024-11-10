package ascon

import (
	"crypto/subtle"
	"fmt"
)

// The differences from the original specification of Ascon are
// * bytes are little-endian instead of big endian
// * new initial values (instead of zero)
// * the rate is doubled
// * increased number of rounds

// AEAD128 provides an implementation of Ascon-AEAD128 from NIST.SP.800-232.
// It implements the crypto/cipher.AEAD interface.
type AEAD128 struct {
	// TODO: k0, k1 uint64?
	key [16]byte
}

func NewAEAD128(key []byte) (*AEAD128, error) {
	a := new(AEAD128)
	a.SetKey(key)
	return a, nil
}

// Sets the key to a new value.
// This method is not safe for concurrent use with other methods.
func (a *AEAD128) SetKey(key []byte) {
	if len(key) != KeySize {
		panic("ascon: wrong key size")
	}
	copy(a.key[:], key)
}

func (*AEAD128) NonceSize() int { return NonceSize }
func (*AEAD128) Overhead() int  { return TagSize }

// Seal encrypts and authenticates a plaintext
// and appends ciphertext to dst, returning the appended slice.
func (a *AEAD128) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(fmt.Sprintf("ascon: bad nonce (len %d)", len(nonce)))
	}

	// Initialize
	// IV || key || nonce
	var s state
	const A, B uint = 12, 8
	s.initAEADle(a.key[:], 128, uint8(A), uint8(B), nonce)
	//log.Printf("%x\n", &s)

	// mix the key in again
	k0 := le64dec(a.key[0:])
	k1 := le64dec(a.key[8:])
	s[3] ^= k0
	s[4] ^= k1

	// Absorb additionalData
	s.mixAdditionalDataLe(additionalData, B)
	// domain-separation constant
	s[4] ^= 0x80 << 56

	// allocate space
	dstLen := len(dst)
	dst = append(dst, make([]byte, len(plaintext)+TagSize)...)

	// Duplex plaintext/ciphertext
	c := s.encryptLe(plaintext, dst[dstLen:], B)

	// mix the key in again
	s[2] ^= k0
	s[3] ^= k1

	// Finalize
	s.rounds(A)

	// Append tag
	t0 := s[3] ^ k0
	t1 := s[4] ^ k1
	le64enc(c[0:], t0)
	le64enc(c[8:], t1)

	return dst
}

func (s *state) initAEADle(key []byte, blockSize, A, B uint8, nonce []byte) {
	if len(key) != KeySize {
		panic("invalid key length")
	}
	s[0] = 1 + uint64(A)<<16 + uint64(B)<<20 + uint64(byte(len(key)*8))<<24 + uint64(blockSize/8)<<40
	s[1] = le64dec(key[0:])
	s[2] = le64dec(key[8:])
	s[3] = le64dec(nonce[0:])
	s[4] = le64dec(nonce[8:])
	//log.Printf("%x\n", &s)
	s.rounds(uint(A))
}

func (s *state) mixAdditionalDataLe(additionalData []byte, B uint) {
	ad := additionalData
	if len(ad) <= 0 {
		// If there is no additional data, nothing is added
		// and no padding is applied
		return
	}

	for len(ad) >= 16 {
		s[0] ^= le64dec(ad)
		s[1] ^= le64dec(ad[8:])
		ad = ad[16:]
		s.rounds(B)
	}

	// last chunk
	if len(ad) > 0 {
		var buf [16]byte
		n := copy(buf[:], ad)
		buf[n] = 1 // Pad
		s[0] ^= le64dec(buf[:])
		s[1] ^= le64dec(buf[8:])
		s.rounds(B)
	} else {
		// Pad
		s[0] ^= 1
		s.rounds(B)
	}
}

func (s *state) encryptLe(plaintext, dst []byte, B uint) []byte {
	p := plaintext
	c := dst
	for len(p) >= 16 {
		s[0] ^= le64dec(p)
		s[1] ^= le64dec(p[8:])
		le64enc(c[0:], s[0])
		le64enc(c[8:], s[1])
		p = p[16:]
		c = c[16:]
		s.rounds(B)
	}
	if len(p) > 0 {
		var buf [16]byte
		n := copy(buf[:], p)
		buf[n] = 1 // Pad
		s[0] ^= le64dec(buf[:])
		s[1] ^= le64dec(buf[8:])
		// may write up to 15 too many bytes
		// but it's okay because we have space reserved
		// for the tag
		le64enc(c, s[0])
		le64enc(c[8:], s[1])
		c = c[n:]
	} else {
		// Pad
		s[0] ^= 1
	}
	// note: no round is done after the final plaintext block
	return c
}

func (a *AEAD128) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic(fmt.Sprintf("ascon: bad nonce (len %d)", len(nonce)))
		// return fail?
	}

	if len(ciphertext) < TagSize {
		return dst, fail
	}
	plaintextSize := len(ciphertext) - TagSize
	expectedTag := ciphertext[plaintextSize:]
	ciphertext = ciphertext[0:plaintextSize]

	dstLen := len(dst)
	dst = append(dst, make([]byte, plaintextSize)...)

	// Initialize
	// IV || key || nonce
	var s state
	const A, B uint = 12, 8
	s.initAEADle(a.key[:], 128, uint8(A), uint8(B), nonce)
	//log.Printf("%x\n", &s)

	// mix the key in again
	k0 := le64dec(a.key[0:])
	k1 := le64dec(a.key[8:])
	s[3] ^= k0
	s[4] ^= k1

	// Absorb additionalData
	s.mixAdditionalDataLe(additionalData, B)
	// domain-separation constant
	s[4] ^= 0x80 << 56

	// Duplex plaintext/ciphertext
	s.decryptLe(ciphertext, dst[dstLen:], B)

	// mix the key in again
	s[2] ^= k0
	s[3] ^= k1

	// Finalize
	s.rounds(A)

	// Compute tag
	t0 := s[3] ^ k0
	t1 := s[4] ^ k1
	// Check tag in constant time
	t0 ^= le64dec(expectedTag[0:])
	t1 ^= le64dec(expectedTag[8:])
	t := uint32(t0>>32) | uint32(t0)
	t |= uint32(t1>>32) | uint32(t1)
	if subtle.ConstantTimeEq(int32(t), 0) == 0 {
		//t0 = s[3] ^ k0
		//t1 = s[4] ^ k1
		//return dst, fmt.Errorf("tag mismatch: got %016x %016x, want %x", t0, t1, expectedTag)
		return dst, fail
	}

	return dst, nil
}

func (s *state) decryptLe(ciphertext, dst []byte, B uint) {
	c := ciphertext
	p := dst
	for len(c) >= 16 {
		x := le64dec(c)
		y := le64dec(c[8:])
		le64enc(p[0:], x^s[0])
		le64enc(p[8:], y^s[1])
		s[0] = x
		s[1] = y
		p = p[16:]
		c = c[16:]
		s.rounds(B)
	}
	si := 0
	if len(c) >= 8 {
		x := le64dec(c)
		le64enc(p, x^s[0])
		s[0] = x
		p = p[8:]
		c = c[8:]
		si = 1
	}
	if len(c) > 0 {
		for i := range p {
			p[i] = c[i] ^ byte(s[si]>>(i*8))
		}

		var x uint64
		for i := range p {
			x |= uint64(p[i]) << (i * 8)
		}
		x |= 1 << (len(c) * 8) // Pad

		s[si] ^= x

		//if len(c) > 0 {
		//	var buf [16]byte
		//	n := copy(buf[:], c)
		//	buf[n] = 1 // pad
		//	x := le64dec(buf[:])
		//	y := le64dec(buf[8:])
		//	x ^= s[0]
		//	y ^= s[1]
		//	le64enc(buf[:], x)
		//	le64enc(buf[8:], y)
		//	s[0] ^= x
		//	s[1] ^= y
		//	copy(p, buf[:n])
	} else {
		// Pad
		s[si] ^= 1
	}
	// note: no round is done after the final plaintext block
}
