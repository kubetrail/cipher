package crypto

import (
	"bufio"
	"bytes"
	"context"
	"math/rand"
	"os"
	"testing"
)

// TestEncryptDecryptData tests if performing the roundtrip
// of encrypting and then decrypting data matches original data
func TestEncryptDecryptData(t *testing.T) {
	priv, pub, err := GenerateKeyPair(DefaultBits2048)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, chunk*10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	bCiphertext := new(bytes.Buffer)
	bPlaintext := new(bytes.Buffer)

	rPlaintext := bufio.NewReader(bytes.NewReader(data))
	rCipherText := bufio.NewReader(bCiphertext)

	wCiphertext := bufio.NewWriter(bCiphertext)
	wPlaintext := bufio.NewWriter(bPlaintext)

	if err := EncryptData(rPlaintext, wCiphertext, pub); err != nil {
		t.Fatal(err)
	}

	if err := wCiphertext.Flush(); err != nil {
		t.Fatal(err)
	}

	if err := DecryptData(rCipherText, wPlaintext, priv); err != nil {
		t.Fatal(err)
	}

	if err := wPlaintext.Flush(); err != nil {
		t.Fatal(err)
	}

	dataRoundTrip := bPlaintext.Bytes()
	if len(data) != len(dataRoundTrip) {
		t.Fatal("data len does not match", len(data), len(dataRoundTrip))
	}

	for i := range data {
		if data[i] != dataRoundTrip[i] {
			t.Fatal("data does not match")
		}
	}
}

func TestNewAesKey(t *testing.T) {
	key, err := NewAesKey()
	if err != nil {
		t.Fatal(err)
	}

	if len(key) != 32 {
		t.Fatal("invalid aes key length, expected 32, got", len(key))
	}

	m := make(map[byte]struct{})
	for i := range key {
		m[key[i]] = struct{}{}
	}

	if len(m) <= 1 {
		t.Fatal("seems like generated AES key is not random")
	}
}

func TestKeySaving(t *testing.T) {
	priv, pub, err := GenerateKeyPair(DefaultBits2048)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := BytesToPrivateKey(PrivateKeyToBytes(priv)); err != nil {
		t.Fatal(err)
	}

	b, err := PublicKeyToBytes(pub)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := BytesToPublicKey(b); err != nil {
		t.Fatal(err)
	}
}

func TestKmsRoundtrip(t *testing.T) {
	ctx := context.Background()

	key, err := NewAesKey()
	if err != nil {
		t.Fatal(err)
	}

	b, err := EncryptWithKms(
		ctx,
		key,
		os.Getenv("GOOGLE_PROJECT_ID"),
		os.Getenv("KMS_LOCATION"),
		os.Getenv("KMS_KEYRING"),
		os.Getenv("KMS_KEY"),
	)
	if err != nil {
		t.Fatal(err)
	}

	b, err = DecryptWithKms(
		ctx,
		b,
		os.Getenv("GOOGLE_PROJECT_ID"),
		os.Getenv("KMS_LOCATION"),
		os.Getenv("KMS_KEYRING"),
		os.Getenv("KMS_KEY"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(b) != len(key) {
		t.Fatal("data len do not match")
	}

	for i := range b {
		if b[i] != key[i] {
			t.Fatal("data values do not match")
		}
	}
}

func TestSignWithPrivateKey(t *testing.T) {
	priv, _, err := GenerateKeyPair(DefaultBits2048)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, chunk*10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(bytes.NewReader(data))
	bb := new(bytes.Buffer)
	w := bufio.NewWriter(bb)

	s1, err := SignWithPrivateKey(data, priv)
	if err != nil {
		t.Fatal(err)
	}

	if err := SignData(r, w, priv); err != nil {
		t.Fatal(err)
	}

	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	s2 := bb.Bytes()

	if len(s1) != len(s2) {
		t.Fatal("sign len does not match")
	}

	for i := range s1 {
		if s1[i] != s2[i] {
			t.Fatal("sign data does not match")
		}
	}
}

func TestVerifyWithPublicKey(t *testing.T) {
	priv, pub, err := GenerateKeyPair(DefaultBits2048)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, chunk*10)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	r := bufio.NewReader(bytes.NewReader(data))

	s, err := SignWithPrivateKey(data, priv)
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyWithPublicKey(data, s, pub); err != nil {
		t.Fatal(err)
	}

	if err := VerifySignature(r, s, pub); err != nil {
		t.Fatal(err)
	}
}
