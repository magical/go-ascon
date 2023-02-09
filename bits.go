// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

// byte manipulation

package ascon

import "encoding/binary"

func be64dec(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func be64enc(b []byte, x uint64) {
	binary.BigEndian.PutUint64(b, x)
}

func be64append(b []byte, x uint64) []byte {
	return append(b, byte(x>>56), byte(x>>48), byte(x>>40), byte(x>>32), byte(x>>24), byte(x>>16), byte(x>>8), byte(x))
}
