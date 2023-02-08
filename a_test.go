// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

package ascon

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"testing"
)

func TestTest(t *testing.T) {
	d := new(digest)
	d.initHash(64, 12, 12, 256)
	log.Printf("%x", &d.a)
}

func TestHash(t *testing.T) {
	d := new(digest)
	d.initHash(64, 12, 12, 256)
	d.Write(nil)
	log.Printf("%x", d.Sum(nil))
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
		d := new(digest)
		d.initHash(64, 12, 12, 256)
		d.Write(b)
		fmt.Fprintf(w, "MD = %X\n", d.Sum(nil))
		fmt.Fprintln(w)
	}
	w.Flush()
}
