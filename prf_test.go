// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import (
	"bufio"
	"fmt"
	"os"
	"testing"
)

func TestMAC(t *testing.T) {
	want := "EB1AF688825D66BF2D53E135F9323315"
	mk := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 256)
		}
		return b
	}
	m := new(MAC)
	m.initMAC(mk(16))
	got := fmt.Sprintf("%X", m.Sum(nil))
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// compare against https://raw.githubusercontent.com/ascon/ascon-c/main/crypto_auth/asconmacv12/LWC_AUTH_KAT_128_128.txt
func TestGenKatMAC(t *testing.T) {
	f, err := os.Create("ascon_mac_kat.txt")
	if err != nil {
		t.Skip("couldn't create output file")
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i % 256)
	}
	for i := 0; i <= 1024; i++ {
		b := make([]byte, i)
		for j := range b {
			b[j] = byte(j % 256)
		}
		fmt.Fprintf(w, "Count = %d\n", i+1)
		fmt.Fprintf(w, "Key = %X\n", key)
		fmt.Fprintf(w, "Msg = %X\n", b)
		m := new(MAC)
		m.initMAC(key)
		m.Write(b)
		fmt.Fprintf(w, "Tag = %X\n", m.Sum(nil))
		fmt.Fprintln(w)
	}
}

func benchMAC(b *testing.B, size int64) {
	b.SetBytes(size)
	out := make([]byte, 0, TagSize)
	msg := make([]byte, size)
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i % 256)
	}
	b.ResetTimer()
	init := new(MAC)
	init.initMAC(key)
	for i := 0; i < b.N; i++ {
		//h.Reset()
		h := *init
		h.Write(msg)
		out = h.Sum(out[:0])
	}
}

func BenchmarkMAC_8(b *testing.B)  { benchMAC(b, 8) }
func BenchmarkMAC_64(b *testing.B) { benchMAC(b, 64) }
func BenchmarkMAC_1k(b *testing.B) { benchMAC(b, 1024) }
func BenchmarkMAC_8k(b *testing.B) { benchMAC(b, 8192) }
