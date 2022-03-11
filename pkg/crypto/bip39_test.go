package crypto

import (
	"bytes"
	"fmt"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"
	"strings"
	"testing"
)

func TestBip39(t *testing.T) {
	entropy, err := bip39.NewEntropy(32 * 8)
	if err != nil {
		t.Fatal(err)
	}
	bip39.SetWordList(wordlists.Spanish) // also the default
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(len(entropy))
	fmt.Println(entropy)
	fmt.Println(mnemonic)

	parts := strings.Split(mnemonic, " ")
	fmt.Println("mnemonic length: ", len(parts))

	entropy2, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(entropy, entropy2) {
		t.Fatal("entropies not equal")
	}

	seed := bip39.NewSeed(mnemonic, "Secret Passphrase")
	fmt.Println(len(seed))
	fmt.Println(seed)

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := masterKey.PublicKey()

	fmt.Println(masterKey)
	fmt.Println(publicKey)

	childKey, err := masterKey.NewChildKey(100)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(childKey)

	fmt.Println("first hardened child idx:", bip32.FirstHardenedChild, 1 > bip32.FirstHardenedChild)
}

func TestRegenerateBip39RootKey(t *testing.T) {
	// derive mnemonic and expectedRootKey from:
	// https://iancoleman.io/bip39/
	mnemonic := "coffee ketchup say work flee bind wine despair special angry east learn mix truly mixture"
	expectedRootKey := "xprv9s21ZrQH143K2PbZxnHf3C6QEtPcp7hSJWbqgv25YjzZVSFfaBJRmMTxtLivFXBQ4xvEFSyc4XC1ZD1SkX98mVRQXDM3KznfnWYfythfdkS"
	seed := bip39.NewSeed(mnemonic, "")
	fmt.Println(len(seed))
	fmt.Println(seed)

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := masterKey.PublicKey()

	fmt.Println(expectedRootKey)
	fmt.Println(masterKey)
	fmt.Println(publicKey)

	if masterKey.String() != expectedRootKey {
		t.Fatal("key does not match expected key value")
	}
}

func TestRegenerateBip39RootKeyBasedOnSecretPassphrase(t *testing.T) {
	// derive mnemonic and expectedRootKey from:
	// https://iancoleman.io/bip39/
	mnemonic := "coffee ketchup say work flee bind wine despair special angry east learn mix truly mixture"
	expectedRootKey := "xprv9s21ZrQH143K3WycGyizt73c5yJVrvgURyoSQ4gbfijbmYkivwHkejWM2LEUuHQG64VDCCrefzZzNAgd3DSPQQUDSxFethTbYDSEa2wYhVV"
	seed := bip39.NewSeed(mnemonic, "thisIsSuperSecret")
	fmt.Println(len(seed))
	fmt.Println(seed)

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := masterKey.PublicKey()

	fmt.Println(expectedRootKey)
	fmt.Println(masterKey)
	fmt.Println(publicKey)

	if masterKey.String() != expectedRootKey {
		t.Fatal("key does not match expected key value")
	}
}

func TestWrongMnemonic(t *testing.T) {
	// derive mnemonic and expectedRootKey from:
	// https://iancoleman.io/bip39/
	mnemonic := "coffee ketchup say work flee bind wine despair special angry east learn mix truly mixture"
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Log("invalid mnemonic 0")
	}

	mnemonic = "coffee ketchup say work flee bind wine despair special angry east learn mix mixture truly"
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Log("invalid mnemonic 1")
	}

	mnemonic = "coffee ketchup say work flee bind wine despair special angry east learn mix truly xyz"
	if !bip39.IsMnemonicValid(mnemonic) {
		t.Log("invalid mnemonic 2")
	}
}

func TestChildKeyCreation(t *testing.T) {
	mnemonic := "client sustain stumble prosper pepper maze prison view omit gold organ youth vintage tattoo practice mutual budget excite bubble economy quick conduct spot end"
	rootKey := "xprv9s21ZrQH143K41PSWfXjMxph7HzErpb6yyNhtPWEpovRDuWgH8vqWGAndNz1oodj88J8JnaNyQMoL2yNKbYWCubfVTF9ux7aiNJCrF8thw7"
	expectedChildKey := "xprv9uZyhhoV56598CN7MPBuvgB8yiPpBdCiQoNjo8vunv99h9xhit2G8qegnth98JSrV2fLsXk6hmUis9HjGNaQdzPEg3dxHyhcqBYFFPeT5p3"
	expectedChildOfChildKey := "xprv9x3Mg4EBHGtCTKSDGYzodXwP7QKvb5h8AfFCc4M6FZNjfwvHSsXkN4SooseucEfkLfydKZupC4tqZAL2SEb5WEbMFEaH333RRyYNjmK2bkM"
	expectedHardenedChildKey := "xprv9uZyhhodQkc7K3ubvSP2QJd7btMKw3hAQRkd9VKzp8UtSZpKhFMB1bn7rBqPL2mARabve7aBAERsU7bqg29GSbCuFeA4SYj78gceQr6gYjt"
	expectedHardenedChildOfChildKey := "xprv9xEbTGTgivg2c3xTTWa8KgLpPXBvufxqP46UCsfLbN4AkCfiE5EXfq9pb5iSR7uM44SLBxdHr2h3ZLHBjNyyZa1WhbHLeXEvuW6XYQPHb3C"
	expectedHardenedChildOfHardenedChildKey := "xprv9xEbTGTq4bCzjqLDHuuABrQ8sCeqtsmTotZKBpCPDUiWeDybe7HHvhsfUER63nXHVfkXhNem9aPg1QUQvs7BKTwTJf7c2nNdzVJZcLaUn4R"
	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatal(err)
	}

	if masterKey.String() != rootKey {
		t.Fatal("master key did not match")
	}

	// derivation path: m/0
	childKey, err := masterKey.NewChildKey(0)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("child key m/0:", childKey)

	if childKey.String() != expectedChildKey {
		t.Fatal("child key did not match")
	}

	// derivation path: m/0/0
	childKey, err = childKey.NewChildKey(0)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("child of child m/0/0:", childKey)

	if childKey.String() != expectedChildOfChildKey {
		t.Fatal("child of child did not match")
	}

	// derivation path: m/0'
	hardenedChild, err := masterKey.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("hardened child m/0':", hardenedChild)

	if hardenedChild.String() != expectedHardenedChildKey {
		t.Fatal("hardened child did not match")
	}

	childOfHardenedChild, err := hardenedChild.NewChildKey(0)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("child of hardened m/0'/0:", childOfHardenedChild)

	if childOfHardenedChild.String() != expectedHardenedChildOfChildKey {
		t.Fatal("child of hardened key did not match")
	}

	hardenededChildOfHardenedChild, err := hardenedChild.NewChildKey(bip32.FirstHardenedChild)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("hardened child of hardened child m/0'/0':", hardenededChildOfHardenedChild)

	if hardenededChildOfHardenedChild.String() != expectedHardenedChildOfHardenedChildKey {
		t.Fatal("hardened child of hardened child did not match")
	}
}
