// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import (
	"bufio"
	"fmt"
	"hash"
	"os"
	"testing"
)

func TestInit(t *testing.T) {
	d := NewHash().(*digest)
	//d.initHash(64, 12, 12, 256)
	got := d.s
	want := [5]uint64{0xee9398aadb67f03d, 0x8bb21831c60f1002, 0xb48a92db98d5da62, 0x43189921b8f8e3e8, 0x348fa5c9d525e140}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("s[%d] = %016x, want %016x", i, got[i], want[i])
		}
	}
}

func TestHash(t *testing.T) {
	want := "7346BC14F036E87AE03D0997913088F5F68411434B3CF8B54FA796A80D251F91"
	got := fmt.Sprintf("%X", hashBytes(nil))
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func hashBytes(b []byte) []byte {
	d := new(digest)
	d.initHash(64, 12, 12, 256)
	d.Write(b)
	return d.Sum(nil)
}

// compare against https://raw.githubusercontent.com/ascon/ascon-c/main/crypto_hash/asconhashv12/LWC_HASH_KAT_256.txt
func TestGenKat(t *testing.T) {
	f, err := os.Create("ascon_hash_kat.txt")
	if err != nil {
		t.Skip("couldn't create output file")
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for i := 0; i <= 1024; i++ {
		b := make([]byte, i)
		for j := range b {
			b[j] = byte(j % 256)
		}
		fmt.Fprintf(w, "Count = %d\n", i+1)
		fmt.Fprintf(w, "Msg = %X\n", b)
		fmt.Fprintf(w, "MD = %X\n", hashBytes(b))
		fmt.Fprintln(w)
	}
	w.Flush()
}

func benchmark(b *testing.B, f func() hash.Hash, size int64) {
	var tmp [Size]byte
	var msg [8192]byte
	b.SetBytes(size)
	h := f()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(msg[:size])
		h.Sum(tmp[:0])
	}
}

// Benchmark the Keccak-f permutation function
func Benchmark256_8(b *testing.B)   { benchmark(b, NewHash, 8) }
func Benchmark256_256(b *testing.B) { benchmark(b, NewHash, 256) }
func Benchmark256_1k(b *testing.B)  { benchmark(b, NewHash, 1024) }
func Benchmark256_8k(b *testing.B)  { benchmark(b, NewHash, 8192) }
