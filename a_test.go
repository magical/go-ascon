// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import (
	"bufio"
	"encoding/hex"
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
	defer w.Flush()
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
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestAEAD(t *testing.T) {
	//Count = 514
	//Key = 000102030405060708090A0B0C0D0E0F
	//Nonce = 000102030405060708090A0B0C0D0E0F
	//PT = 000102030405060708090A0B0C0D0E
	//AD = 000102030405060708090A0B0C0D0E0F1011
	//CT = 77AA511159627C4B855E67F95B3ABFA1FA8B51439743E4C8B41E4E76B40460
	//
	//Count = 496
	//AD =
	//CT = BC820DBDF7A4631C5B29884AD6917516D420A5BC2E5357D010818F0B5F7859
	var (
		key   = unhex("000102030405060708090A0B0C0D0E0F")
		nonce = key
		text  = unhex("000102030405060708090A0B0C0D0E")
		ad    = unhex("000102030405060708090A0B0C0D0E0F1011")
		want  = "77AA511159627C4B855E67F95B3ABFA1FA8B51439743E4C8B41E4E76B40460"
		//ad   = unhex("")
		//want = "BC820DBDF7A4631C5B29884AD6917516D420A5BC2E5357D010818F0B5F7859"
	)
	a := new(AEAD)
	copy(a.key[:], key)
	c := a.Seal(nil, nonce, text, ad)
	got := fmt.Sprintf("%X", c)
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestGenKatAEAD(t *testing.T) {
	f, err := os.Create("ascon_aead_kat.txt")
	if err != nil {
		t.Skip("couldn't create output file")
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	num := 1

	mk := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i % 256)
		}
		return b
	}
	for i := 0; i <= 32; i++ {
		for j := 0; j <= 32; j++ {

			key := mk(16)
			nonce := mk(16)
			msg := mk(i)
			ad := mk(j)

			fmt.Fprintf(w, "Count = %d\n", num)
			fmt.Fprintf(w, "Key = %X\n", key)
			fmt.Fprintf(w, "Nonce = %X\n", nonce)
			fmt.Fprintf(w, "PT = %X\n", msg)
			fmt.Fprintf(w, "AD = %X\n", ad)
			a := new(AEAD)
			copy(a.key[:], key)
			c := a.Seal(nil, nonce, msg, ad)
			fmt.Fprintf(w, "CT = %X\n", c)
			fmt.Fprintln(w)
			num += 1
		}
	}
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
func Benchmark256_8(b *testing.B)  { benchmark(b, NewHash, 8) }
func Benchmark256_64(b *testing.B) { benchmark(b, NewHash, 64) }
func Benchmark256_1k(b *testing.B) { benchmark(b, NewHash, 1024) }
func Benchmark256_8k(b *testing.B) { benchmark(b, NewHash, 8192) }
