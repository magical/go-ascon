// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import "hash"

const Size = 256 / 8      // bytes
const BlockSize = 64 / 8  // bytes
const stateSize = 320 / 8 // bytes

// digest implements hash.Hash
type digest struct {
	s    state
	buf  [8]byte
	len  int   // number of bytes in buf
	size int   // size of the output
	b    uint8 // number of rounds for the pB round function
}

func NewHash() hash.Hash {
	d := new(digest)
	d.Reset()
	return d
}

// The size of the final hash, in bytes.
func (d *digest) Size() int { return Size }

// The data rate of the sponge, in bytes.
// Writes which are a multiple of BlockSize will be more performant.
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	//fmt.Println("resetting")
	//d.initHash(BlockSize*8, 12, 12, Size*8)
	d.s[0] = 0xee9398aadb67f03d
	d.s[1] = 0x8bb21831c60f1002
	d.s[2] = 0xb48a92db98d5da62
	d.s[3] = 0x43189921b8f8e3e8
	d.s[4] = 0x348fa5c9d525e140
	d.buf = [8]byte{}
	d.len = 0
	d.b = 12
}

// Ascon-Hash: l=256, hash=256, datablock=64, a=12, b=12

func (d *digest) initHash(blockSize, a, b uint8, h uint32) {
	d.s[0] = uint64(blockSize)<<48 + uint64(a)<<40 + uint64(a-b)<<32 + uint64(h)
	d.s[1] = 0
	d.s[2] = 0
	d.s[3] = 0
	d.s[4] = 0
	d.b = b
	d.roundA()
}

func (d *digest) roundA() { roundGeneric(&d.s, roundc[:]) }
func (d *digest) roundB() { roundGeneric(&d.s, roundc[12-d.b:]) }

func (d *digest) Write(b []byte) (int, error) {
	written := len(b)
	const bs = BlockSize
	// try to empty the buffer, if it isn't empty already
	if d.len > 0 && d.len+len(b) >= bs {
		n := copy(d.buf[d.len:bs], b)
		d.len += n
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
		d.len += n
	}
	return written, nil
}

func (d0 *digest) Sum(b []byte) []byte {
	d := *d0

	if d.len >= len(d.buf) {
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

	// Squeeze
	for i := 0; i < Size/8; i++ {
		if i != 0 {
			d.roundB()
		}
		b = be64append(b, d.s[0])
	}
	return b
}
