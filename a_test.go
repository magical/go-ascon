// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import (
	"bufio"
	"fmt"
	"hash"
	"log"
	"os"
	"testing"
)

func TestInit(t *testing.T) {
	d := new(digest)
	d.initHash(64, 12, 12, 256)
	log.Printf("%x", &d.s)
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
