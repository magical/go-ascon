package ascon

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"testing"
)

func TestGenKatAEAD128(t *testing.T) {
	if !*genkat {
		t.Skip("skipping without -genkat flag")
	}
	f, err := os.Create("ascon_aead_128_kat.txt")
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
			a, _ := NewAEAD128(key)
			c := a.Seal(nil, nonce, msg, ad)
			fmt.Fprintf(w, "CT = %X\n", c)
			fmt.Fprintln(w)

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

			num += 1
		}
	}
}
