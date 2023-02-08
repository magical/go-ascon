// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import "hash"

const Size = 256 / 8      // bytes
const BlockSize = 64 / 8  // bytes
const stateSize = 320 / 8 // bytes

// digest implements hash.Hash
type digest struct {
	s    [5]uint64
	buf  [8]byte
	len  int   // number of bytes in buf
	size int   // size of the output
	b    uint8 // number of rounds for the pB round function
}

func NewHash() hash.Hash {
	d := &digest{}
	d.Reset()
	return d
}

// The size of the final hash, in bytes.
func (d *digest) Size() int { return d.size }

// The data rate of the sponge, in bytes.
// Writes which are a multiple of BlockSize will be more performant.
func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Reset() {
	//fmt.Println("resetting")
	d.s = [5]uint64{}
	d.initHash(BlockSize*8, 12, 12, Size*8)
	d.buf = [8]byte{}
	d.len = 0
}

// Ascon-Hash: l=256, hash=256, datablock=64, a=12, b=12

func (d *digest) initHash(r, a, b uint8, h uint32) {
	d.s[0] = uint64(r)<<48 + uint64(a)<<40 + uint64(a-b)<<32 + uint64(h)
	d.s[1] = 0
	d.s[2] = 0
	d.s[3] = 0
	d.s[4] = 0
	d.b = b
	d.size = int(h / 8)
	roundGeneric(&d.s, roundc[:]) // TODO: pA
}

func (d *digest) Write(b []byte) (int, error) {
	written := len(b)
	bs := d.BlockSize()
	// try to empty the buffer, if it isn't empty already
	if d.len > 0 && d.len+len(b) >= bs {
		n := copy(d.buf[d.len:bs], b)
		d.len += n
		b = b[n:]
		if d.len == bs {
			d.absorb() // TODO: pB
		}
	}
	// absorb bytes directly, skipping the buffer
	for len(b) >= bs {
		d.s[0] ^= be64dec(b)
		roundGeneric(&d.s, roundc[:]) // TODO: pB
		b = b[bs:]
	}
	// store any remaining bytes in the buffer
	if len(b) > 0 {
		n := copy(d.buf[d.len:bs], b)
		d.len += n
	}
	return written, nil
}

func (d *digest) absorb() {
	//fmt.Printf("Flushing with %d bytes\n", d.len)
	d.s[0] ^= be64dec(d.buf[0:])
	roundGeneric(&d.s, roundc[:]) // TODO: pB
	d.len = 0
}

func (d0 *digest) Sum(b []byte) []byte {
	d := *d0

	if d.len >= len(d.buf) {
		panic("ascon: internal error")
	}

	// Pad with a 1 followed by zeroes
	bs := d.BlockSize()
	for i := d.len; i < bs; i++ {
		d.buf[i] = 0
	}
	d.buf[d.len] |= 0x80
	d.len = bs

	// absorb the last block
	d.absorb() // TODO: pA

	// Squeeze
	for i := 0; i < d.size/8; i++ {
		if i != 0 {
			roundGeneric(&d.s, roundc[:]) // TODO: pB
		}
		b = be64enc(b, d.s[0])
	}
	return b
}

func be64dec(b []byte) uint64 {
	return uint64(b[0])<<56 | uint64(b[1])<<48 | uint64(b[2])<<40 | uint64(b[3])<<32 | uint64(b[4])<<24 | uint64(b[5])<<16 | uint64(b[6])<<8 | uint64(b[7])<<0
}
func be64enc(b []byte, x uint64) []byte {
	return append(b, byte(x>>56), byte(x>>48), byte(x>>40), byte(x>>32), byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}
