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

type AEAD struct {
	key [16]byte
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
	d := new(digest)
	d.initAEAD(key, 64, 12, 6, nonce)
	//log.Printf("%x\n", &d.s)

	// mix the key in again
	d.s[3] ^= be64dec(key[0:])
	d.s[4] ^= be64dec(key[8:])

	// Absorb additionalData
	d.mixAdditionalData(additionalData)
	// domain-separation constant
	d.s[4] ^= 1

	// allocate space
	dstLen := len(dst)
	dst = append(dst, make([]byte, len(plaintext)+TagSize)...)

	// Duplex plaintext/ciphertext
	p := plaintext
	c := dst[dstLen:]
	for len(p) >= 8 {
		d.s[0] ^= be64dec(p)
		binary.BigEndian.PutUint64(c, d.s[0])
		p = p[8:]
		c = c[8:]
		d.roundB()
	}
	if len(p) > 0 {
		d.buf = [8]byte{}
		n := copy(d.buf[:], p)
		// Pad
		d.buf[n] |= 0x80
		d.s[0] ^= be64dec(d.buf[:])
		// may write up to 7 too many bytes
		// but it's okay because we have space reserved
		// for the tag
		binary.BigEndian.PutUint64(c, d.s[0])
		c = c[n:]
	} else {
		// Pad
		d.s[0] ^= 0x80 << 56
	}
	// note: no round is done after the final plaintext block

	// mix the key in again
	d.s[1] ^= be64dec(key[0:])
	d.s[2] ^= be64dec(key[8:])

	// Finalize
	d.roundA()

	// Append tag
	t0 := d.s[3] ^ be64dec(key[0:])
	t1 := d.s[4] ^ be64dec(key[8:])
	binary.BigEndian.PutUint64(c[0:], t0)
	binary.BigEndian.PutUint64(c[8:], t1)

	return dst
}

func (d *digest) initAEAD(key []byte, r, a, b uint8, nonce []byte) {
	if len(key) != KeySize {
		panic("invalid key length")
	}
	d.s[0] = uint64(byte(len(key)*8))<<56 + uint64(r)<<48 + uint64(a)<<40 + uint64(a-b)<<32
	d.s[1] = be64dec(key[0:])
	d.s[2] = be64dec(key[8:])
	d.s[3] = be64dec(nonce[0:])
	d.s[4] = be64dec(nonce[8:])
	//log.Printf("%x\n", &d.s)
	d.b = b
	d.roundA()
}

func (d *digest) mixAdditionalData(additionalData []byte) {
	ad := additionalData
	if len(ad) > 0 {
		for len(ad) >= 8 {
			d.s[0] ^= be64dec(ad)
			ad = ad[8:]
			d.roundB()
		}
		if len(ad) > 0 {
			d.buf = [8]byte{}
			n := copy(d.buf[:], ad)
			// Pad
			d.buf[n] |= 0x80
			d.s[0] ^= be64dec(d.buf[:])
			d.roundB()
		} else {
			// Pad
			d.s[0] ^= 0x80 << 56
			d.roundB()
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
	d := new(digest)
	d.initAEAD(key, 64, 12, 6, nonce)
	//log.Printf("%x\n", &d.s)

	// mix the key in again
	d.s[3] ^= be64dec(key[0:])
	d.s[4] ^= be64dec(key[8:])

	// Absorb additionalData
	d.mixAdditionalData(additionalData)
	// domain-separation constant
	d.s[4] ^= 1

	// Duplex plaintext/ciphertext
	for len(c) >= 8 {
		x := be64dec(c)
		binary.BigEndian.PutUint64(p, x^d.s[0])
		d.s[0] = x
		p = p[8:]
		c = c[8:]
		d.roundB()
	}
	if len(c) > 0 {
		for i := range p {
			p[i] = c[i] ^ byte(d.s[0]>>(56-i*8))
		}

		var x uint64
		for i := range p {
			x |= uint64(p[i]) << (56 - i*8)
		}
		x |= 0x80 << (56 - (len(c) * 8)) // Pad

		d.s[0] ^= x
	} else {
		// Pad
		d.s[0] ^= 0x80 << 56
	}
	// note: no round is done after the final plaintext block

	// mix the key in again
	d.s[1] ^= be64dec(key[0:])
	d.s[2] ^= be64dec(key[8:])

	// Finalize
	d.roundA()

	// Compute tag
	t0 := d.s[3] ^ be64dec(key[0:])
	t1 := d.s[4] ^ be64dec(key[8:])
	// Check tag in constant time
	t0 ^= be64dec(expectedTag[0:])
	t1 ^= be64dec(expectedTag[8:])
	t := uint32(t0>>32) | uint32(t0)
	t |= uint32(t1>>32) | uint32(t1)
	if subtle.ConstantTimeEq(int32(t), 0) == 0 {
		//t0 = d.s[3] ^ be64dec(key[0:])
		//t1 = d.s[4] ^ be64dec(key[8:])
		//return dst, fmt.Errorf("tag mismatch: got %016x %016x, want %x", t0, t1, expectedTag)
		return dst, fail
	}

	return dst, nil
}
