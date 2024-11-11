// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import "errors"

const HashSize = 256 / 8  // bytes
const BlockSize = 64 / 8  // bytes
const stateSize = 320 / 8 // bytes

// digest implements hash.Hash
type digest struct {
	s   state
	buf [8]byte
	len uint8 // number of bytes in buf

	initialized bool
	doneWriting bool
}

// Hash256 provides an implementation of Ascon-Hash256 from NIST.SP.800-232.
type Hash256 struct{ digest }

func NewHash256() *Hash256 {
	h := new(Hash256)
	h.digest.reset()
	return h
}

// The size of the final hash, in bytes.
func (h *Hash256) Size() int { return HashSize }

func (h *Hash256) Reset() { h.digest.reset() }

// Sum appends a message digest to [b] and returns the new slice.
// Does not modify the hash state.
func (h *Hash256) Sum(b []byte) []byte { return h.digest.sum(b) }

// Clone returns a new copy of h.
func (h *Hash256) Clone() *Hash256 {
	new := *h
	return &new
}

func (h *Hash256) Write(p []byte) (int, error) {
	if h.digest.initialized == false {
		h.Reset()
	}
	h.digest.write(p)
	return len(p), nil
}

// Xof128 is an implementation of the Ascon-XOF128 arbitrary-length hash algorithm.
// It implements the golang.org/x/crypto/sha3.ShakeHash interface (minus Clone).
type Xof128 struct{ digest }

func NewXof128() *Xof128 {
	x := new(Xof128)
	x.Reset()
	return x
}

// Clone returns a new copy of x.
func (x *Xof128) Clone() *Xof128 {
	new := *x
	return &new
}

func (x *Xof128) Reset() {
	x.digest.initHash(3, 64, 12, 12, 0)
	x.digest.len = 0
	x.digest.initialized = true
	x.digest.doneWriting = false
}

func (x *Xof128) Write(p []byte) (int, error) {
	if x.digest.initialized == false {
		x.Reset()
	}
	x.digest.write(p)
	return len(p), nil
}

func (x *Xof128) Read(p []byte) (int, error) {
	if x.digest.initialized == false {
		x.Reset()
	}
	x.digest.read(p)
	return len(p), nil
}

// Cxof128 is an implementation of the Ascon-CXOF128 customized arbitrary-length hash algorithm.
// It implements the golang.org/x/crypto/sha3.ShakeHash interface (minus Clone).
type Cxof128 struct {
	digest       digest
	initialState *state
}

func NewCxof128(customizationString string) (*Cxof128, error) {
	// "The length of the customization string shall be at most 2048 bits (i.e., 256 bytes)."
	if len(customizationString) > 256 {
		return nil, errors.New("ascon: customization string too long")
	}
	x := new(Cxof128)
	x.digest.initHash(4, 64, 12, 12, 0)
	// absorb Z_0, the length of the customization string (in bits) encoded as a uint64
	x.digest.s[0] ^= uint64(len(customizationString)) * 8
	x.digest.permute()
	// absorb the customization string
	x.digest.write([]byte(customizationString))
	x.digest.finish() // flush buffer and pad
	// save the initial state
	s := x.digest.s // make a copy
	x.initialState = &s
	x.digest.initialized = true
	return x, nil
}

// Clone returns a new copy of x.
func (x *Cxof128) Clone() *Cxof128 {
	new := *x
	return &new
}

func (x *Cxof128) Reset() {
	if x.digest.initialized == false {
		panic("ascon: reset of uninitialized CXOF")
	}
	x.digest.s = *x.initialState
	x.digest.len = 0
	x.digest.initialized = true
	x.digest.doneWriting = false
}

func (x *Cxof128) Write(p []byte) (int, error) {
	if x.digest.initialized == false {
		panic("ascon: write to uninitialized CXOF")
	}
	x.digest.write(p)
	return len(p), nil
}

func (x *Cxof128) Read(p []byte) (int, error) {
	if x.digest.initialized == false {
		panic("ascon: read from uninitialized CXOF")
	}
	x.digest.read(p)
	return len(p), nil
}

// The data rate of the sponge, in bytes.
// Writes which are a multiple of BlockSize will be more performant.
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) reset() {
	//fmt.Println("resetting")
	//d.initHash(2, BlockSize*8, 12, 12, 256)
	d.s[0] = 0x9b1e5494e934d681
	d.s[1] = 0x4bc3a01e333751d2
	d.s[2] = 0xae65396c6b34b81a
	d.s[3] = 0x3c7fd4a4d56a4db3
	d.s[4] = 0x1a5c464906c5976d
	d.buf = [8]byte{}
	d.len = 0
	d.initialized = true
	d.doneWriting = false
}

// Ascon-Hash: v=2, l=256, hash=256, datablock=64, a=12, b=12
// Ascon-Xof:  v=3, l=256, hash=0,   datablock=64, a=12, b=12

func (d *digest) initHash(v, blockSize, a, b uint8, h uint32) {
	//d.s[0] = uint64(blockSize)<<48 + uint64(a)<<40 + uint64(a-b)<<32 + uint64(h)
	d.s[0] = uint64(v) + uint64(a)<<16 + uint64(b)<<20 + uint64(h)<<24 + uint64(blockSize/8)<<40
	d.s[1] = 0
	d.s[2] = 0
	d.s[3] = 0
	d.s[4] = 0
	d.permute()
}

func (d *digest) permute() { roundGeneric(&d.s, 12) }

func (d *digest) write(b []byte) {
	if d.doneWriting {
		panic("ascon: Write called after Read")
	}
	const bs = BlockSize
	// try to empty the buffer, if it isn't empty already
	if d.len > 0 && int(d.len)+len(b) >= bs {
		n := copy(d.buf[d.len:bs], b)
		d.len += uint8(n)
		b = b[n:]
		if d.len == bs {
			d.s[0] ^= le64dec(d.buf[0:])
			d.permute()
			d.len = 0
		}
	}
	// absorb bytes directly, skipping the buffer
	for len(b) >= bs {
		d.s[0] ^= le64dec(b)
		d.permute()
		b = b[bs:]
	}
	// store any remaining bytes in the buffer
	if len(b) > 0 {
		n := copy(d.buf[d.len:bs], b)
		d.len += uint8(n)
	}
}

func (d *digest) finish() {
	if int(d.len) >= len(d.buf) {
		panic("ascon: internal error")
	}

	// Pad with a 1 followed by zeroes
	const bs = BlockSize
	for i := d.len + 1; i < bs; i++ {
		d.buf[i] = 0
	}
	d.buf[d.len] = 1

	// absorb the last block
	d.s[0] ^= le64dec(d.buf[0:])
	d.permute()
	d.len = 0
}

func (d *digest) clone() *digest {
	d0 := *d
	return &d0
}

func (d *digest) sum(b []byte) []byte {
	d = d.clone()
	d.finish()

	// Squeeze
	for i := 0; i < HashSize/8; i++ {
		if i != 0 {
			d.permute()
		}
		b = le64append(b, d.s[0])
	}
	return b
}

// Reads len(p) bytes of hash output. The error is always nil.
func (d *digest) read(p []byte) {
	if !d.doneWriting {
		d.finish()
		d.doneWriting = true
	}
	if len(p) <= 0 {
		return
	}

	// Squeeze

	// invariants:
	//  if d.len == 8 then the buffer is empty and permute has NOT been called since the previous block
	//  if d.len == 0 then the buffer is empty and permute HAS been called since the previous block, or this is the first block
	//  if 0 < d.len < 8 then we have bytes to read in d.buf

	// Copy out any leftover bytes from the previous block
	const bs = BlockSize
	if d.len > 0 && d.len < bs {
		n := copy(p, d.buf[d.len:bs])
		d.len += uint8(n)
		if d.len < bs || len(p) == n {
			return
		}
		p = p[n:]
		// the buffer is empty. We still have bytes to read
	}

	// d.len == 0 or 8

	// Copy whole blocks if we can
	if len(p) >= 8 && d.len == 0 {
		d.len = 8
		le64enc(p, d.s[0])
		p = p[8:]
	}
	for len(p) >= 8 {
		d.permute()
		le64enc(p, d.s[0])
		p = p[8:]
	}

	// Partial block
	if len(p) > 0 {
		// fill the buffer
		if d.len == 8 {
			d.permute()
		}
		le64enc(d.buf[:], d.s[0])
		n := copy(p, d.buf[:])
		d.len = uint8(n)
	}
}

// Reads len(p) bytes of hash output in one shot.
// Must be a multiple of BlockSize.
// Used for testing Read.
func (d *digest) readAll(p []byte) {
	if d.doneWriting {
		panic("internal error")
	}
	d.finish()
	d.doneWriting = true

	if len(p)%BlockSize != 0 {
		panic("internal error")
	}

	for i := 0; i < len(p); i += BlockSize {
		if i != 0 {
			d.permute()
		}
		le64enc(p[i:], d.s[0])
	}
}
