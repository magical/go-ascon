package ascon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type jsonPrompt struct {
	TcId int `json:"tcId"`

	// Hash, XOF, CXOF
	Msg    string `json:"msg"`
	MsgLen int    `json:"len"`
	// XOF, CXOF
	OutLen int `json:"outLen"`
	// CXOF
	Cs    string `json:"cs"`
	CsLen int    `json:"csLen"`

	// AEAD
	Key        string
	SecondKey  string // for nonce masking
	Nonce      string
	PayloadLen int
	Pt         string
	Ct         string
	Ad         string
	AdLen      int
	Tag        string
	TagLen     int
}

type jsonExpected struct {
	TcId int `json:"tcId"`

	// Hash, XOF, CXOF
	Md string `json:"md"`

	// AEAD
	Tag        string
	Ct         string
	Pt         string
	TestPassed *bool
}

func loadJson(t *testing.T, dir string) ([]jsonPrompt, []jsonExpected) {
	var prompts []jsonPrompt
	f, err := os.Open(filepath.Join(dir, "simple.json"))
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("skipping test because %s/simple.json is missing. to download the json files, run getjson.sh", dir)
		}
		t.Fatal(err)
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(&prompts)
	if err != nil {
		t.Fatal(err)
	}

	var expectedResults []jsonExpected
	f, err = os.Open(filepath.Join(dir, "want.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = json.NewDecoder(f).Decode(&expectedResults)
	if err != nil {
		t.Fatal(err)
	}

	if len(prompts) == 0 {
		t.Fatal("no tests loaded")
	}
	if len(prompts) != len(expectedResults) {
		t.Fatal("mismatch between simple.json and want.json")
	}

	return prompts, expectedResults
}

func TestHashJson(t *testing.T) {
	prompts, expectedResults := loadJson(t, "json/hash")
	for tcIndex, tc := range prompts {
		want := &expectedResults[tcIndex]
		msg, err := hex.DecodeString(tc.Msg)
		if err != nil {
			t.Error("msg", err)
			continue
		}

		h := NewHash256()
		h.Write(msg)
		checkBytes(t, tc.TcId, "sum", h.Sum(nil), want.Md)
		// check that Sum is idempotent
		checkBytes(t, tc.TcId, "second sum", h.Sum(nil), want.Md)
	}
}

func TestXofJson(t *testing.T) {
	prompts, expectedResults := loadJson(t, "json/xof")
	for tcIndex, tc := range prompts {
		x := NewXof128()
		message, err := hex.DecodeString(tc.Msg)
		if err != nil {
			t.Error("msg", err)
			continue
		}
		n, err := x.Write(message)
		if n != len(message) || err != nil {
			if n != len(message) {
				t.Error("short write")
			}
			if err != nil {
				t.Errorf("unexpected error from Write: %v", err)
			}
			continue
		}
		output := make([]byte, tc.OutLen/8)
		n, err = x.Read(output)
		if n != len(output) || err != nil {
			if n != len(message) {
				t.Error("short read")
			}
			if err != nil {
				t.Errorf("unexpected error from Read: %v", err)
			}
		}
		want := &expectedResults[tcIndex]
		checkBytes(t, tc.TcId, "output", output, want.Md)
	}
}

func TestXCOFJson(t *testing.T) {
	prompts, expectedResults := loadJson(t, "json/cxof")

	for tcIndex, tc := range prompts {
		custom, err := hex.DecodeString(tc.Cs)
		if err != nil {
			t.Error("msg", err)
			continue
		}
		message, err := hex.DecodeString(tc.Msg)
		if err != nil {
			t.Error("cs", err)
			continue
		}

		x, err := NewCxof128(string(custom))
		if err != nil {
			t.Error(err)
			continue
		}
		n, err := x.Write(message)
		if n != len(message) || err != nil {
			if n != len(message) {
				t.Error("short write")
			}
			if err != nil {
				t.Errorf("unexpected error from Write: %v", err)
			}
			continue
		}
		output := make([]byte, tc.OutLen/8)
		n, err = x.Read(output)
		if n != len(output) || err != nil {
			if n != len(message) {
				t.Error("short read")
			}
			if err != nil {
				t.Errorf("unexpected error from Read: %v", err)
			}
		}
		want := &expectedResults[tcIndex]
		checkBytes(t, tc.TcId, "output", output, want.Md)
	}
}

func TestAEADJson(t *testing.T) {
	prompts, expectedResults := loadJson(t, "json/aead")
	_ = prompts
	_ = expectedResults
	for tcIndex, tc := range prompts {
		if tc.TagLen != 8*TagSize {
			//t.Errorf("skipping test %d with unsupported tag size", tc.TcId)
			continue
		}
		key, err := hex.DecodeString(tc.Key)
		if err != nil {
			t.Error("key", err)
			continue
		}
		nonce, err := hex.DecodeString(tc.Nonce)
		if err != nil {
			t.Error("nonce", err)
			continue
		}
		ad, err := hex.DecodeString(tc.Ad)
		if err != nil {
			t.Error("ad", err)
			continue
		}

		a, err := NewAEAD128(key)
		if err != nil {
			t.Error("unexpected error: ", err)
			continue
		}

		if tc.SecondKey != "" {
			mask, err := hex.DecodeString(tc.SecondKey)
			if err != nil {
				t.Error("secondKey", err)
				continue
			}
			for i, x := range mask {
				nonce[i] ^= x
			}
		}

		want := &expectedResults[tcIndex]
		if tc.Pt != "" {
			text, err := hex.DecodeString(tc.Pt)
			if err != nil {
				t.Error("pt", err)
				continue
			}
			ciphertext := a.Seal(nil, nonce, text, ad)
			checkBytes(t, tc.TcId, "ct", ciphertext, want.Ct+want.Tag)
		}
		if tc.Ct != "" {
			ciphertext, err := hex.DecodeString(tc.Ct + tc.Tag)
			if err != nil {
				t.Error("ct", err)
				continue
			}
			text, err := a.Open(nil, nonce, ciphertext, ad)
			if err != nil {
				if want.TestPassed == nil || *want.TestPassed == true {
					t.Errorf("tcId=%d: unexpected error: %v", tc.TcId, err)
					continue
				}
			} else {
				if want.TestPassed != nil && *want.TestPassed == false {
					t.Errorf("tcId=%d: Open unexpectedly suceeded", tc.TcId)
					continue
				}
			}
			if want.Pt != "" {
				checkBytes(t, tc.TcId, "pt", text, want.Pt)
			}
		}
	}
}

func checkBytes(t *testing.T, id int, name string, actual []byte, expected string) {
	if expected != fmt.Sprintf("%X", actual) {
		t.Errorf("tcId=%d: %s: want %s, got %X", id, name, expected, actual)
	}
}
