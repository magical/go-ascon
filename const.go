// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

// Section 2.6.1, Table 4 (page 13)
// p12 uses 0..12
// p8 uses 4..12
// p6 uses 6..12
var roundc = [12]uint8{
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
