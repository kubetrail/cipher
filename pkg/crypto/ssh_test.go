package crypto

import (
	"crypto/rsa"
	"fmt"
	"golang.org/x/crypto/ssh"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicKeyParsing(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa_test.pub"))
	if err != nil {
		t.Fatal(err)
	}
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}

	_ = parsedKey
}

func TestPrivateKeyParsing(t *testing.T) {
	b, err := os.ReadFile("/home/sdeoras/id_rsa")
	//b, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".ssh", "id_rsa_test"))
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("bytes len", len(b))

	obj, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		if _, ok := err.(*ssh.PassphraseMissingError); ok {
			passphrase := []byte("this is a test")
			obj, err = ssh.ParseRawPrivateKeyWithPassphrase(b, passphrase)
			if err != nil {
				t.Fatal("passphrase did not work", err)
			}
		} else {
			t.Fatalf("error type is not passphrase related: %v, %T\n", err, err)
		}
	}

	key, ok := obj.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("not a rsa private key")
	}

	fmt.Println(key.Size())
}
