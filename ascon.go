// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import "math/bits"

// https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf

type state [5]uint64

func roundGeneric(s *state, rounds []uint8) {
	var x0, x1, x2, x3, x4 uint64
	x0 = s[0]
	x1 = s[1]
	x2 = s[2]
	x3 = s[3]
	x4 = s[4]

	for _, r := range rounds {
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

		// Linear layer
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
