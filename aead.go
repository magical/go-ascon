package ascon

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	NonceSize = 128 / 8
	KeySize   = 128 / 8
	TagSize   = 128 / 8
	//BlockSize
)

// AEAD provides an implementation of Ascon-128.
// It implements the crypto/cipher.AEAD interface.
type AEAD struct {
	// TODO: k0, k1 uint64?
	key [16]byte
}

func NewAEAD(key []byte) (*AEAD, error) {
	a := new(AEAD)
	a.SetKey(key)
	return a, nil
}

// Sets the key to a new value.
// This method is not safe for concurrent use with other methods.
func (a *AEAD) SetKey(key []byte) {
	if len(key) != 16 {
		panic("ascon: wrong key size")
	}
	copy(a.key[:], key)
}

func (_ *AEAD) NonceSize() int { return NonceSize }
func (_ *AEAD) Overhead() int  { return TagSize }

// Seal encrypts and authenticates a plaintext
// and appends ciphertext to dst, returning the appended slice.
func (aead *AEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	key := aead.key[:]
	if len(nonce) != NonceSize {
		panic(fmt.Sprintf("ascon: bad nonce (len %d)", len(nonce)))
	}

	// Initialize
	// IV || key || nonce
	var s state
	A, B := 12, 6
	s.initAEAD(key, 64, uint8(A), uint8(B), nonce)
	//log.Printf("%x\n", &s)

	// mix the key in again
	s[3] ^= be64dec(key[0:])
	s[4] ^= be64dec(key[8:])

	// Absorb additionalData
	s.mixAdditionalData(additionalData, B)
	// domain-separation constant
	s[4] ^= 1

	// allocate space
	dstLen := len(dst)
	dst = append(dst, make([]byte, len(plaintext)+TagSize)...)

	// Duplex plaintext/ciphertext
	p := plaintext
	c := dst[dstLen:]
	for len(p) >= 8 {
		s[0] ^= be64dec(p)
		binary.BigEndian.PutUint64(c, s[0])
		p = p[8:]
		c = c[8:]
		s.rounds(B)
	}
	if len(p) > 0 {
		var buf [8]byte
		n := copy(buf[:], p)
		// Pad
		buf[n] |= 0x80
		s[0] ^= be64dec(buf[:])
		// may write up to 7 too many bytes
		// but it's okay because we have space reserved
		// for the tag
		binary.BigEndian.PutUint64(c, s[0])
		c = c[n:]
	} else {
		// Pad
		s[0] ^= 0x80 << 56
	}
	// note: no round is done after the final plaintext block

	// mix the key in again
	s[1] ^= be64dec(key[0:])
	s[2] ^= be64dec(key[8:])

	// Finalize
	s.rounds(A)

	// Append tag
	t0 := s[3] ^ be64dec(key[0:])
	t1 := s[4] ^ be64dec(key[8:])
	binary.BigEndian.PutUint64(c[0:], t0)
	binary.BigEndian.PutUint64(c[8:], t1)

	return dst
}

func (s *state) initAEAD(key []byte, blockSize, A, B uint8, nonce []byte) {
	if len(key) != KeySize {
		panic("invalid key length")
	}
	s[0] = uint64(byte(len(key)*8))<<56 + uint64(blockSize)<<48 + uint64(A)<<40 + uint64(A-B)<<32
	s[1] = be64dec(key[0:])
	s[2] = be64dec(key[8:])
	s[3] = be64dec(nonce[0:])
	s[4] = be64dec(nonce[8:])
	//log.Printf("%x\n", &s)
	s.rounds(int(A))
}

func (s *state) mixAdditionalData(additionalData []byte, B int) {
	ad := additionalData
	if len(ad) > 0 {
		for len(ad) >= 8 {
			s[0] ^= be64dec(ad)
			ad = ad[8:]
			s.rounds(B)
		}
		if len(ad) > 0 {
			var buf [8]byte
			n := copy(buf[:], ad)
			// Pad
			buf[n] |= 0x80
			s[0] ^= be64dec(buf[:])
			s.rounds(B)
		} else {
			// Pad
			s[0] ^= 0x80 << 56
			s.rounds(B)
		}
	} else {
		// If there is no additional data, no padding is applied
	}
}

var fail = errors.New("ascon: decryption failed")

func (aead *AEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	key := aead.key[:]
	if len(nonce) != NonceSize {
		panic(fmt.Sprintf("ascon: bad nonce (len %d)", len(nonce)))
		// return fail?
	}

	if len(ciphertext) < TagSize {
		return dst, fail
	}
	plaintextSize := len(ciphertext) - TagSize
	expectedTag := ciphertext[plaintextSize:]
	c := ciphertext[0:plaintextSize]

	dstLen := len(dst)
	dst = append(dst, make([]byte, plaintextSize)...)
	p := dst[dstLen:]

	// Initialize
	// IV || key || nonce
	var s state
	A, B := 12, 6
	s.initAEAD(key, 64, uint8(A), uint8(B), nonce)
	//log.Printf("%x\n", &s)

	// mix the key in again
	s[3] ^= be64dec(key[0:])
	s[4] ^= be64dec(key[8:])

	// Absorb additionalData
	s.mixAdditionalData(additionalData, B)
	// domain-separation constant
	s[4] ^= 1

	// Duplex plaintext/ciphertext
	for len(c) >= 8 {
		x := be64dec(c)
		binary.BigEndian.PutUint64(p, x^s[0])
		s[0] = x
		p = p[8:]
		c = c[8:]
		s.rounds(B)
	}
	if len(c) > 0 {
		for i := range p {
			p[i] = c[i] ^ byte(s[0]>>(56-i*8))
		}

		var x uint64
		for i := range p {
			x |= uint64(p[i]) << (56 - i*8)
		}
		x |= 0x80 << (56 - (len(c) * 8)) // Pad

		s[0] ^= x
	} else {
		// Pad
		s[0] ^= 0x80 << 56
	}
	// note: no round is done after the final plaintext block

	// mix the key in again
	s[1] ^= be64dec(key[0:])
	s[2] ^= be64dec(key[8:])

	// Finalize
	s.rounds(A)

	// Compute tag
	t0 := s[3] ^ be64dec(key[0:])
	t1 := s[4] ^ be64dec(key[8:])
	// Check tag in constant time
	t0 ^= be64dec(expectedTag[0:])
	t1 ^= be64dec(expectedTag[8:])
	t := uint32(t0>>32) | uint32(t0)
	t |= uint32(t1>>32) | uint32(t1)
	if subtle.ConstantTimeEq(int32(t), 0) == 0 {
		//t0 = s[3] ^ be64dec(key[0:])
		//t1 = s[4] ^ be64dec(key[8:])
		//return dst, fmt.Errorf("tag mismatch: got %016x %016x, want %x", t0, t1, expectedTag)
		return dst, fail
	}

	return dst, nil
}

func (s *state) rounds(r int) { roundGeneric(s, roundc[12-r:]) }
