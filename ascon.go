// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

// Ascon round function/permutation
// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf

package ascon

import "math/bits"

type state [5]uint64

// Section 2.6.1, Table 4 (page 13)
// p12 uses 0..12
// p8 uses 4..12
// p6 uses 6..12
var roundConstant = [12]uint8{
	0x00000000000000f0,
	0x00000000000000e1,
	0x00000000000000d2,
	0x00000000000000c3,
	0x00000000000000b4,
	0x00000000000000a5,
	0x0000000000000096,
	0x0000000000000087,
	0x0000000000000078,
	0x0000000000000069,
	0x000000000000005a,
	0x000000000000004b,
}

func roundGeneric(s *state, numRounds uint) {
	var x0, x1, x2, x3, x4 uint64
	x0 = s[0]
	x1 = s[1]
	x2 = s[2]
	x3 = s[3]
	x4 = s[4]

	for _, r := range roundConstant[12-numRounds:] {
		// Section 2.6.1, Addition of Constants (page 13)
		x2 ^= uint64(r)

		// Section 2.6.2 Substitution layer
		// and Section 7.3, Figure 5 (page 42)
		x0 ^= x4
		x4 ^= x3
		x2 ^= x1

		t0 := ^x0
		t1 := ^x1
		t2 := ^x2
		t3 := ^x3
		t4 := ^x4

		t0 &= x1
		t1 &= x2
		t2 &= x3
		t3 &= x4
		t4 &= x0

		x0 ^= t1
		x1 ^= t2
		x2 ^= t3
		x3 ^= t4
		x4 ^= t0

		x1 ^= x0
		x0 ^= x4
		x3 ^= x2
		x2 = ^x2

		// Section 2.6.3 Linear Diffusion Layer
		x0 = x0 ^ bits.RotateLeft64(x0, -19) ^ bits.RotateLeft64(x0, -28)
		x1 = x1 ^ bits.RotateLeft64(x1, -61) ^ bits.RotateLeft64(x1, -39)
		x2 = x2 ^ bits.RotateLeft64(x2, -1) ^ bits.RotateLeft64(x2, -6)
		x3 = x3 ^ bits.RotateLeft64(x3, -10) ^ bits.RotateLeft64(x3, -17)
		x4 = x4 ^ bits.RotateLeft64(x4, -7) ^ bits.RotateLeft64(x4, -41)
	}

	s[0] = x0
	s[1] = x1
	s[2] = x2
	s[3] = x3
	s[4] = x4
}
