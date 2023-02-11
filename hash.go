// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

const HashSize = 256 / 8  // bytes
const BlockSize = 64 / 8  // bytes
const stateSize = 320 / 8 // bytes

// digest implements hash.Hash
type digest struct {
	s   state
	buf [8]byte
	len uint8 // number of bytes in buf
	b   uint8 // number of rounds for the pB round function

	doneWriting bool
}

type Hash struct{ digest }

func NewHash() *Hash {
	h := new(Hash)
	h.digest.reset(12)
	return h
}

func NewHasha() *Hash {
	h := new(Hash)
	h.digest.reset(8)
	return h
}

// The size of the final hash, in bytes.
func (h *Hash) Size() int { return HashSize }

func (h *Hash) Reset() { h.digest.reset(h.b) }

func (h *Hash) Write(p []byte) (int, error) {
	h.digest.write(p)
	return len(p), nil
}

// Xof is an implementation of the Ascon-Xof arbitrary-length hash algorithm.
// It implements the golang.org/x/crypto/sha3.ShakeHash interface except for Clone.
type Xof struct{ digest }

func NewXof() *Xof {
	x := new(Xof)
	x.Reset()
	return x
}

func (x *Xof) Reset() {
	x.digest.initHash(64, 12, 12, 0)
	x.digest.len = 0
	x.digest.doneWriting = false
}

func (x *Xof) Write(p []byte) (int, error) {
	x.digest.write(p)
	return len(p), nil
}

func (x *Xof) Read(p []byte) (int, error) {
	x.digest.read(p)
	return len(p), nil
}

// The data rate of the sponge, in bytes.
// Writes which are a multiple of BlockSize will be more performant.
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) reset(b uint8) {
	//fmt.Println("resetting")
	//d.initHash(BlockSize*8, 12, 12, Size*8)
	switch b {
	case 12:
		d.s[0] = 0xee9398aadb67f03d
		d.s[1] = 0x8bb21831c60f1002
		d.s[2] = 0xb48a92db98d5da62
		d.s[3] = 0x43189921b8f8e3e8
		d.s[4] = 0x348fa5c9d525e140
		d.b = b
	default:
		d.initHash(BlockSize*8, 12, b, 256)
	}
	d.buf = [8]byte{}
	d.len = 0
	d.doneWriting = false
}

// Ascon-Hash: l=256, hash=256, datablock=64, a=12, b=12
// Ascon-Xof:  l=256, hash=0,   datablock=64, a=12, b=12

func (d *digest) initHash(blockSize, a, b uint8, h uint32) {
	d.s[0] = uint64(blockSize)<<48 + uint64(a)<<40 + uint64(a-b)<<32 + uint64(h)
	d.s[1] = 0
	d.s[2] = 0
	d.s[3] = 0
	d.s[4] = 0
	d.b = b
	d.roundA()
}

func (d *digest) roundA() { roundGeneric(&d.s, 12) }
func (d *digest) roundB() { roundGeneric(&d.s, uint(d.b)) }

func (d *digest) write(b []byte) (int, error) {
	if d.doneWriting {
		panic("ascon: Write called after Read")
	}
	written := len(b)
	const bs = BlockSize
	// try to empty the buffer, if it isn't empty already
	if d.len > 0 && int(d.len)+len(b) >= bs {
		n := copy(d.buf[d.len:bs], b)
		d.len += uint8(n)
		b = b[n:]
		if d.len == bs {
			d.s[0] ^= be64dec(d.buf[0:])
			d.roundB()
			d.len = 0
		}
	}
	// absorb bytes directly, skipping the buffer
	for len(b) >= bs {
		d.s[0] ^= be64dec(b)
		d.roundB()
		b = b[bs:]
	}
	// store any remaining bytes in the buffer
	if len(b) > 0 {
		n := copy(d.buf[d.len:bs], b)
		d.len += uint8(n)
	}
	return written, nil
}

func (d *digest) finish() {
	if int(d.len) >= len(d.buf) {
		panic("ascon: internal error")
	}

	// Pad with a 1 followed by zeroes
	const bs = BlockSize
	for i := d.len; i < bs; i++ {
		d.buf[i] = 0
	}
	d.buf[d.len] |= 0x80

	// absorb the last block
	d.s[0] ^= be64dec(d.buf[0:])
	d.roundA()
	d.len = 0
}

func (d0 *digest) Sum(b []byte) []byte {
	d := *d0
	d.finish()

	// Squeeze
	for i := 0; i < HashSize/8; i++ {
		if i != 0 {
			d.roundB()
		}
		b = be64append(b, d.s[0])
	}
	return b
}

// Reads len(p) bytes of hash output. The error is always nil.
func (d *digest) read(p []byte) (int, error) {
	if !d.doneWriting {
		d.finish()
		d.doneWriting = true
	}
	read := len(p)
	if len(p) <= 0 {
		return 0, nil
	}

	// Squeeze

	// invariants:
	//  if d.len == 8 then the buffer is empty and roundB has NOT been called since the previous block
	//  if d.len == 0 then the buffer is empty and roundB HAS been called since the previous block, or this is the first block
	//  if 0 < d.len < 8 then we have bytes to read in d.buf

	// Copy out any leftover bytes from the previous block
	const bs = BlockSize
	if d.len > 0 && d.len < bs {
		n := copy(p, d.buf[d.len:bs])
		d.len += uint8(n)
		if d.len < bs || len(p) == n {
			return n, nil
		}
		p = p[n:]
		// the buffer is empty. We still have bytes to read
	}

	// d.len == 0 or 8

	// Copy whole blocks if we can
	if len(p) >= 8 && d.len == 0 {
		d.len = 8
		be64enc(p, d.s[0])
		p = p[8:]
	}
	for len(p) >= 8 {
		d.roundB()
		be64enc(p, d.s[0])
		p = p[8:]
	}

	// Partial block
	if len(p) > 0 {
		// fill the buffer
		if d.len == 8 {
			d.roundB()
		}
		be64enc(d.buf[:], d.s[0])
		n := copy(p, d.buf[:])
		d.len = uint8(n)
	}
	return read, nil
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
			d.roundB()
		}
		be64enc(p[i:], d.s[0])
	}
}
