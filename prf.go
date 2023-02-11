// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

// Ascon-PRF and Ascon-MAC are specified in "Ascon PRF, MAC, and Short-Input MAC"
// by Christoph Dobraunig and Maria Eichlseder and Florian Mendel and Martin Schläffer.
// https://eprint.iacr.org/2021/1574

type MAC struct {
	s   state
	buf [256 / 8]byte
	len uint8 // number of bytes in buf
}

func (d *MAC) BlockSize() int { return len(d.buf) }
func (d *MAC) Size() int      { return TagSize }

func (d *MAC) Write(p []byte) (int, error) {
	d.write(p)
	return len(p), nil
}

func (d *MAC) initMAC(key []byte) {
	if len(key) != KeySize {
		panic("ascon: wrong key length")
	}
	const r, t, a = 128, 128, 12
	k := len(key) * 8
	d.s[0] = uint64(uint8(k))<<56 + uint64(r)<<48 + uint64(0x80|a)<<40 + uint64(t)
	d.s[1] = be64dec(key[0:])
	d.s[2] = be64dec(key[8:])
	d.s[3] = 0
	d.s[4] = 0
	d.len = 0
	d.round()
}

func (d *MAC) write(b []byte) {
	const bs = BlockSize * 4
	// try to empty the buffer, if it isn't empty already
	if d.len > 0 && int(d.len)+len(b) >= bs {
		n := copy(d.buf[d.len:bs], b)
		d.len += uint8(n)
		b = b[n:]
		if d.len == bs {
			d.s[0] ^= be64dec(d.buf[0:])
			d.s[1] ^= be64dec(d.buf[8:])
			d.s[2] ^= be64dec(d.buf[16:])
			d.s[3] ^= be64dec(d.buf[24:])
			d.round()
			d.len = 0
		}
	}
	// absorb bytes directly, skipping the buffer
	for len(b) >= bs {
		d.s[0] ^= be64dec(b[0:])
		d.s[1] ^= be64dec(b[8:])
		d.s[2] ^= be64dec(b[16:])
		d.s[3] ^= be64dec(b[24:])
		d.round()
		b = b[bs:]
	}
	// store any remaining bytes in the buffer
	if len(b) > 0 {
		n := copy(d.buf[d.len:bs], b)
		d.len += uint8(n)
	}
}

func (d *MAC) finish() {
	if int(d.len) >= len(d.buf) {
		panic("ascon: internal error")
	}

	// Pad with a 1 followed by zeroes
	const bs = BlockSize * 4
	if d.len == 0 {
		d.s[0] ^= 0x80 << 56
	} else {
		for i := d.len; i < bs; i++ {
			d.buf[i] = 0
		}
		d.buf[d.len] |= 0x80

		// absorb the last block
		d.s[0] ^= be64dec(d.buf[0:])
		d.s[1] ^= be64dec(d.buf[8:])
		d.s[2] ^= be64dec(d.buf[16:])
		d.s[3] ^= be64dec(d.buf[24:])
		d.len = 0
	}

	d.s[4] ^= 0x01
	d.round()
}

func (d0 *MAC) Sum(b []byte) []byte {
	d := *d0
	d.finish()

	// Squeeze
	b = be64append(b, d.s[0])
	b = be64append(b, d.s[1])

	return b
}

func (d *MAC) round() { d.s.rounds(12) }
