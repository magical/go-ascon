// Copyright © 2023 by Andrew Ekstedt <andrew.ekstedt@gmail.com>
// All rights reserved. See LICENSE for details.

// +build go1.18

package ascon

import (
	"bytes"
	"testing"
)

func newAEAD(key []byte) *AEAD {
	a := new(AEAD)
	copy(a.key[:], key)
	return a
}

func FuzzAEAD(f *testing.F) {
	key := []byte("my special key..")
	nonce := []byte("my special nonce")

	f.Add(byte(0x00), byte(0x00), 8, 0, byte(0x00), 0)
	f.Fuzz(func(t *testing.T,
		msgByte, adByte byte,
		msgLen, adLen int,
		noise byte, noiseIndex int,
	) {
		a := newAEAD(key)
		if msgLen < 0 || msgLen > 0x4000 {
			return
		}
		if adLen < 0 || adLen > 0x100 {
			return
		}
		msg := bytes.Repeat([]byte{msgByte}, msgLen)
		ad := bytes.Repeat([]byte{adByte}, adLen)
		ciphertext := a.Seal(nil, nonce, msg, ad)
		decrypted, err := a.Open(nil, nonce, ciphertext, ad)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(decrypted, msg) {
			t.Error("plaintext mismatch")
		}

		doNoise := func(name string, thing []byte) {
			if len(thing) > 0 {
				i := noiseIndex % len(thing)
				thing[i] ^= noise
				_, err := a.Open(nil, nonce, ciphertext, ad)
				thing[i] ^= noise
				if err == nil {
					t.Error("Open succeeded with a modified ", name)
				}
			}
		}
		if noise != 0 {
			doNoise("nonce", nonce)
			doNoise("ciphertext", ciphertext)
			doNoise("additional data", ad)
		}
	})

}
