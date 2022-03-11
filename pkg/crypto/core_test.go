package crypto

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"math/rand"
	"os"
	"sync"
	"testing"

	"github.com/monnand/dhkx"
	"golang.org/x/crypto/pbkdf2"
)

func TestGenerateKeyPairReader(t *testing.T) {
	b := make([]byte, 2048*64)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(bytes.NewReader(b))

	if _, _, err := GenerateKeyPairReader(br, DefaultBits2048); err != nil {
		t.Fatal(err)
	}
}

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

	if !bytes.Equal(data, dataRoundTrip) {
		t.Fatal("data does not match")
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

	if !bytes.Equal(b, key) {
		t.Fatal("data values do not match")
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

	if !bytes.Equal(s1, s2) {
		t.Fatal("sign data does not match")
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

// https://crypto.stackexchange.com/questions/9509/aes-encryption-using-a-diffie-hellman-key-exchange
func TestDiffieHellmanKeyExchange(t *testing.T) {
	bobChan := make(chan []byte)
	aliceChan := make(chan []byte)

	var aliceKey []byte
	var bobKey []byte

	wg := new(sync.WaitGroup)
	wg.Add(2)

	go func() {
		defer wg.Done()
		// Get a group. Use the default one would be enough.
		g, _ := dhkx.GetGroup(0)

		// Generate a private key from the group.
		// Use the default random number generator.
		priv, _ := g.GeneratePrivateKey(nil)

		// Get the public key from the private key.
		pub := priv.Bytes()

		go func() {
			bobChan <- pub
		}()

		b := <-aliceChan

		key := dhkx.NewPublicKey(b)

		k, _ := g.ComputeKey(key, priv)

		aliceKey = k.Bytes()
	}()

	go func() {
		defer wg.Done()
		// Get a group. Use the default one would be enough.
		g, _ := dhkx.GetGroup(0)

		// Generate a private key from the group.
		// Use the default random number generator.
		priv, _ := g.GeneratePrivateKey(nil)

		// Get the public key from the private key.
		pub := priv.Bytes()

		go func() {
			aliceChan <- pub
		}()

		b := <-bobChan

		key := dhkx.NewPublicKey(b)

		k, _ := g.ComputeKey(key, priv)

		bobKey = k.Bytes()
	}()

	wg.Wait()

	aliceSalt := md5.Sum(aliceKey)
	bobSalt := md5.Sum(bobKey)
	aliceKey = pbkdf2.Key(aliceKey, aliceSalt[:], 4096, 32, sha256.New)
	bobKey = pbkdf2.Key(bobKey, bobSalt[:], 4096, 32, sha256.New)

	aliceCipher, err := EncryptWithAesKey([]byte("hello"), aliceKey)
	if err != nil {
		t.Fatal(err)
	}

	bobCipher, err := EncryptWithAesKey([]byte("hello"), bobKey)
	if err != nil {
		t.Fatal(err)
	}

	alicePlaintext, err := DecryptWithAesKey(bobCipher, aliceKey)
	if err != nil {
		t.Fatal(err)
	}

	bobPlaintext, err := DecryptWithAesKey(aliceCipher, bobKey)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(alicePlaintext, bobPlaintext) {
		t.Fatal("decrypted messages not same")
	}
}
