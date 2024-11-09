// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"testing"
)

var genkat = flag.Bool("genkat", false, "generate KAT files")

func TestInit(t *testing.T) {
	// Test that the hardcoded initial state equals the computed values
	h := NewHash()
	g := new(Hash)
	g.initHash(64, 12, 12, 256)
	got := h.s
	want := g.s
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Hash: s[%d] = %016x, want %016x", i, got[i], want[i])
		}
	}

	h = NewHasha()
	got = h.s
	g.initHash(64, 12, 8, 256)
	want = g.s
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("Hasha: s[%d] = %016x, want %016x", i, got[i], want[i])
		}
	}
}

var hashTests = []struct {
	msgLen    int
	hexDigest string
}{
	{0, "7346BC14F036E87AE03D0997913088F5F68411434B3CF8B54FA796A80D251F91"},
	{1, "8DD446ADA58A7740ECF56EB638EF775F7D5C0FD5F0C2BBBDFDEC29609D3C43A2"},
	{7, "DD409CCC0C60CD7F474C0BEED1E1CD48140AD45D5136DC5FDA5EBE283DF8D3F6"},
	{8, "F4C6A44B29915D3D57CF928A18EC6226BB8DD6C1136ACD24965F7E7780CD69CF"},
	{15, "9E48E03E8AAE0B9930DFF1E801007BC7105D6BD6CAAF16E3C31569D8942FC423"},
	{16, "D4E56C4841E2A0069D4F07E61B2DCA94FD6D3F9C0DF78393E6E8292921BC841D"},
	{100, "809CFCD3619777D73B162109EFCE633B272C8AFF18578D0169CB99F4783D136E"},
}

func TestHash(t *testing.T) {
	for _, tt := range hashTests {
		msg := make([]byte, tt.msgLen)
		for i := range msg {
			msg[i] = byte(i)
		}
		want := tt.hexDigest
		h := NewHash()
		h.Write(msg)
		got := fmt.Sprintf("%X", h.Sum(nil))
		if got != want {
			t.Errorf("msgLen=%d: got %s, want %s", tt.msgLen, got, want)
		}
		// check that Sum is idempotent
		got = fmt.Sprintf("%X", h.Sum(nil))
		if got != want {
			t.Errorf("msglen=%d: got %s, want %s", tt.msgLen, got, want)
		}
	}
}

var hashaTests = []struct {
	msgLen    int
	hexDigest string
}{
	{0, "AECD027026D0675F9DE7A8AD8CCF512DB64B1EDCF0B20C388A0C7CC617AAA2C4"},
	{1, "5A55F0367763D334A3174F9C17FA476EB9196A22F10DAF29505633572E7756E4"},
	{7, "6B6AD8A90EAB00DCCC182DF1CEC764E706461E76D303863728B8590B772E9082"},
	{8, "BE9332E10AD16137322968BBEC1776BA3F4ECDC1183DB7DBE1AC98BD66FCE7B6"},
	{15, "2CABC9FB4DF0C8EB2ED789EB28AC5D464762B1F98C176C370548496CA9229BAC"},
	{16, "EA1CB73639BFA0C6DE4E60960F4F73510FE4481340F1D956A59E9DD2166F9A99"},
	{100, "ABD438E75E0C435B3C63365037211E4A12D9B8ACBF54A43B281736E3ABF39485"},
}

func TestHasha(t *testing.T) {
	for _, tt := range hashaTests {
		h := NewHasha()
		msg := make([]byte, tt.msgLen)
		for i := range msg {
			msg[i] = byte(i)
		}
		h.Write(msg)
		want := tt.hexDigest
		got := fmt.Sprintf("%X", h.Sum(nil))
		if got != want {
			t.Errorf("msglen=%d: got %s, want %s", tt.msgLen, got, want)
		}
		// check that Sum is idempotent
		got = fmt.Sprintf("%X", h.Sum(nil))
		if got != want {
			t.Errorf("msglen=%d: got %s, want %s", tt.msgLen, got, want)
		}
	}
}

func hashBytes(b []byte) []byte {
	h := NewHash()
	h.Write(b)
	return h.Sum(nil)
}

// compare against https://raw.githubusercontent.com/ascon/ascon-c/main/crypto_hash/asconhashv12/LWC_HASH_KAT_256.txt
func TestGenKatHash(t *testing.T) {
	if !*genkat {
		t.Skip("skipping without -genkat flag")
	}
	f, err := os.Create("ascon_hash_kat.txt")
	if err != nil {
		t.Fatal(err)
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

func TestGenKatXof(t *testing.T) {
	if !*genkat {
		t.Skip("skipping without -genkat flag")
	}
	f, err := os.Create("ascon_xof_kat.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	sum := make([]byte, 32)
	for i := 0; i <= 1024; i++ {
		b := make([]byte, i)
		for j := range b {
			b[j] = byte(j % 256)
		}
		fmt.Fprintf(w, "Count = %d\n", i+1)
		fmt.Fprintf(w, "Msg = %X\n", b)
		x := NewXof()
		x.Write(b)
		x.Read(sum)
		fmt.Fprintf(w, "MD = %X\n", sum)
		fmt.Fprintln(w)
	}
}

func TestXofChunks(t *testing.T) {
	init := NewXof()
	init.Write([]byte("abc"))

	const N = 2016

	expected := make([]byte, N)
	d := init.Clone()
	d.readAll(expected)

	for chunkSize := 1; chunkSize < N; chunkSize++ {
		output := make([]byte, N)
		d := init.Clone()
		for i := 0; i < len(output); i += chunkSize {
			end := i + chunkSize
			if end > len(output) {
				end = len(output)
			}
			nread, err := d.Read(output[i:end])
			if len := end - i; nread != len || err != nil {
				t.Errorf("Read(%d) returned n=%v, err=%v expected n=%v, err=nil", len, nread, err, len)
			}
		}
		if !bytes.Equal(output, expected) {
			t.Errorf("Chunked read of %d bytes: got %X, want %X", chunkSize, output, expected)
		}
	}

	output := make([]byte, N)
	d = init.Clone()
	for i, j := 0, 0; i < len(output); i, j = i+j, j+1 {
		end := i + j
		if end > len(output) {
			end = len(output)
		}
		d.Read(output[i:end])
		if !bytes.Equal(output[i:end], expected[i:end]) {
			t.Errorf("Read of %d bytes after %d: got %X, want %X", j, i, output[i:end], expected[i:end])
		}
	}
	if !bytes.Equal(output, expected) {
		t.Error("Chunked reads differ from expected")
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var _ cipher.AEAD = (*AEAD)(nil)

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
	a, _ := NewAEAD(key)
	c := a.Seal(nil, nonce, text, ad)
	got := fmt.Sprintf("%X", c)
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestGenKatAEAD(t *testing.T) {
	if !*genkat {
		t.Skip("skipping without -genkat flag")
	}
	f, err := os.Create("ascon_aead_kat.txt")
	if err != nil {
		t.Fatal(err)
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
			a, _ := NewAEAD(key)
			c := a.Seal(nil, nonce, msg, ad)
			fmt.Fprintf(w, "CT = %X\n", c)
			fmt.Fprintln(w)
			num += 1

			// TODO: do these tests even without -genkat
			if d, err := a.Open(nil, nonce, c, ad); err != nil {
				t.Errorf("decryption failed (Count = %d): %v", num, err)
			} else if !bytes.Equal(d, msg) {
				t.Errorf("decrypted ciphertext does not match the plaintext (Count = %d): got %X, want %X", num, d, msg)
			}

			c[num%len(c)] ^= 1
			if _, err := a.Open(nil, nonce, c, ad); err == nil {
				t.Errorf("decryption succeeded unexpectedly (Count = %d)", num)
			}
		}
	}
}

// TODO: test overlap

func benchHash(b *testing.B, f func() *Hash, size int64) {
	b.SetBytes(size)
	var tmp = make([]byte, 0, HashSize)
	var msg = make([]byte, size)
	h := f()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(msg[:size])
		h.Sum(tmp[:0])
	}
}

func BenchmarkHash(b *testing.B) {
	b.Run("8", func(b *testing.B) { benchHash(b, NewHash, 8) })
	b.Run("64", func(b *testing.B) { benchHash(b, NewHash, 64) })
	b.Run("1k", func(b *testing.B) { benchHash(b, NewHash, 1024) })
	b.Run("8k", func(b *testing.B) { benchHash(b, NewHash, 8192) })
}

func BenchmarkHasha(b *testing.B) {
	b.Run("8", func(b *testing.B) { benchHash(b, NewHasha, 8) })
	b.Run("64", func(b *testing.B) { benchHash(b, NewHasha, 64) })
	b.Run("1k", func(b *testing.B) { benchHash(b, NewHasha, 1024) })
	b.Run("8k", func(b *testing.B) { benchHash(b, NewHasha, 8192) })
}

func benchSeal(b *testing.B, size int64) {
	b.SetBytes(size)
	var nonce = make([]byte, NonceSize)
	var dst = make([]byte, 0, size+TagSize)
	var msg = make([]byte, size)
	var key = make([]byte, KeySize)
	a, err := NewAEAD(key)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		a.Seal(dst[:0], nonce, msg, nil)
	}
}

func BenchmarkSeal(b *testing.B) {
	b.Run("8", func(b *testing.B) { benchSeal(b, 8) })
	b.Run("64", func(b *testing.B) { benchSeal(b, 64) })
	b.Run("1k", func(b *testing.B) { benchSeal(b, 1024) })
	b.Run("8k", func(b *testing.B) { benchSeal(b, 8192) })
}

func benchOpen(b *testing.B, size int64) {
	b.SetBytes(size)
	var nonce = make([]byte, NonceSize)
	var msg = make([]byte, size)
	var key = make([]byte, KeySize)
	a, err := NewAEAD(key)
	if err != nil {
		b.Fatal(err)
	}
	ciphertext := a.Seal(nil, nonce, msg, nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := a.Open(msg[:0], nonce, ciphertext, nil)
		if err != nil {
			b.Fatal("decryption failed")
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	b.Run("8", func(b *testing.B) { benchOpen(b, 8) })
	b.Run("64", func(b *testing.B) { benchOpen(b, 64) })
	b.Run("1k", func(b *testing.B) { benchOpen(b, 1024) })
	b.Run("8k", func(b *testing.B) { benchOpen(b, 8192) })
}

func benchRead(b *testing.B, size int64) {
	b.SetBytes(size)
	var buf = make([]byte, size)
	x := NewXof()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		x.Read(buf)
	}
}

func BenchmarkXofRead(b *testing.B) {
	b.Run("Unaligned", func(b *testing.B) { benchRead(b, 31) }) // 31 is a Mersenne prime
	b.Run("Aligned", func(b *testing.B) { benchRead(b, 32) })
	b.Run("Large", func(b *testing.B) { benchRead(b, 16<<10) })
}
