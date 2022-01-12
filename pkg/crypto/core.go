package crypto

import (
	"bufio"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"hash/crc32"
	"io"

	kms "cloud.google.com/go/kms/apiv1"
	kmsv1 "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	chunk           = 1024 * 1000
	DefaultBits2048 = 2048
)

// EncryptedBlock represents the structure of the encrypted data.
// Data is encrypted using symmetric key, and the key is then
// encrypted using asymmetric key and then kept next to the data.
// Each block of data has its own data encryption key (DEK),
// however, all data encryption keys are encrypted using the same
// key encryption key (KEK).
type EncryptedBlock struct {
	DataEncryptionKey []byte `json:"d,omitempty"`
	Ciphertext        []byte `json:"c,omitempty"`
}

// Marshal serializes encrypted block
func (g *EncryptedBlock) Marshal() ([]byte, error) {
	return json.Marshal(g)
}

// DecryptData works with input reader and writer and the private key
// scanning the input one line at a time (this is specific to how this
// tool stores encrypted data) and spawning goroutines to decrypt such
// chunks of data. wait channel is used to synchronize the writing
// but reading input and decrypting process is not synchronized because
// it does not have to be.
func DecryptData(r io.Reader, w io.Writer, priv *rsa.PrivateKey) error {
	scanner := bufio.NewScanner(r)
	const maxCapacity = chunk * 2
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	wait := make(chan error)
	go func() {
		wait <- nil
	}()

	for scanner.Scan() {
		wait = writeBlock(
			wait,
			decryptBlock(
				[]byte(
					scanner.Text(),
				),
				priv,
			),
			w,
		)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if err := <-wait; err != nil {
		return err
	}

	return nil
}

// EncryptData works with reader and writer and the public key. It
// makes no assumptions about the input data and reads byte buffer chunks
// and spawns goroutines to encrypt each block. wait is used to synchronize
// writing to the writer, but encryption of each block is not synchronized.
func EncryptData(r io.Reader, w io.Writer, pub *rsa.PublicKey) error {
	wait := make(chan error)
	go func() {
		wait <- nil
	}()

	for {
		buf := make([]byte, chunk)
		n, err := r.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}

		buf = buf[:n]

		wait = writeBlock(
			wait,
			encryptBlock(buf, pub),
			w,
		)
	}

	if err := <-wait; err != nil {
		return err
	}

	return nil
}

// NewAesKey generates new AES key
func NewAesKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		err := fmt.Errorf("could not create a rand AES key: %w", err)
		return nil, err
	}

	return key[:], nil
}

// GenerateKeyPair generates a new RSA key pair
func GenerateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		err := fmt.Errorf("could not generate RSA key pair: %w", err)
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}

// PrivateKeyToBytes private key to bytes
func PrivateKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	return privBytes
}

// PublicKeyToBytes public key to bytes
func PublicKeyToBytes(pub *rsa.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		err := fmt.Errorf("could not marshal public key: %w", err)
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return pubBytes, nil
}

// BytesToPrivateKey bytes to private key
func BytesToPrivateKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse private key: %w", err)
		return nil, err
	}
	return key, nil
}

// BytesToPublicKey bytes to public key
func BytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	d, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse public key: %w", err)
		return nil, err
	}
	key, ok := d.(*rsa.PublicKey)
	if !ok {
		err := fmt.Errorf("type assertion to public key failed")
		return nil, err
	}
	return key, nil
}

// EncryptWithPublicKey encrypts data with public key
func EncryptWithPublicKey(msg []byte, pub *rsa.PublicKey) ([]byte, error) {
	hash := sha512.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub, msg, nil)
	if err != nil {
		err := fmt.Errorf("could not encypt with public key: %w", err)
		return nil, err
	}
	return ciphertext, nil
}

// DecryptWithPrivateKey decrypts data with private key
func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		err := fmt.Errorf("could not decrypt with private key: %w", err)
		return nil, err
	}
	return plaintext, nil
}

// SignWithPrivateKey signs data using private key
func SignWithPrivateKey(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		err := fmt.Errorf("could not create sha256: %w", err)
		return nil, err
	}
	d := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
}

// SignData signs data using private key
func SignData(r io.Reader, w io.Writer, priv *rsa.PrivateKey) error {
	h := sha256.New()
	for {
		buf := make([]byte, chunk)
		n, err := r.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}

		buf = buf[:n]

		if _, err := h.Write(buf); err != nil {
			err := fmt.Errorf("could not create sha256: %w", err)
			return err
		}
	}

	d := h.Sum(nil)
	sign, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, d)
	if err != nil {
		return fmt.Errorf("could not sign data: %w", err)
	}

	if _, err := w.Write(sign); err != nil {
		return fmt.Errorf("could not write sign to writer: %w", err)
	}

	return nil
}

// VerifyWithPublicKey verifies the signature for the input data
func VerifyWithPublicKey(data []byte, sig []byte, pub *rsa.PublicKey) error {
	h := sha256.New()
	if _, err := h.Write(data); err != nil {
		return fmt.Errorf("failed to write to sha256 writer: %w", err)
	}
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d, sig)
}

// VerifySignature verifies the signature for the input data
func VerifySignature(r io.Reader, sig []byte, pub *rsa.PublicKey) error {
	h := sha256.New()
	for {
		buf := make([]byte, chunk)
		n, err := r.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n == 0 {
			break
		}

		buf = buf[:n]

		if _, err := h.Write(buf); err != nil {
			err := fmt.Errorf("could not create sha256: %w", err)
			return err
		}
	}
	d := h.Sum(nil)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, d, sig)
}

// EncryptWithAesKey encrypts data using AES key
func EncryptWithAesKey(data, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		err := fmt.Errorf("could not create a new aes cipher: %w", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		err := fmt.Errorf("could not create new gcm from cipher: %w", err)
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		err := fmt.Errorf("could not populate nonce: %w", err)
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

// DecryptWithAesKey decrypts data using AES key
func DecryptWithAesKey(data, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		err := fmt.Errorf("could not create a new aes cipher: %w", err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		err := fmt.Errorf("could not create new gcm from cipher: %w", err)
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		err := fmt.Errorf("invalid cipher text, length less than nonce")
		return nil, err
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		err := fmt.Errorf("could not decrypt cipher text: %w", err)
		return nil, err
	}

	return plaintext, nil
}

// EncryptWithKms encrypts input data using Google KMS. You must have a service account
// referenced by env. var. GOOGLE_APPLICATION_CREDENTIALS
func EncryptWithKms(ctx context.Context,
	data []byte, project, location, keyring, key string) ([]byte, error) {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		err := fmt.Errorf("failed to create kms client: %w", err)
		return nil, err
	}
	defer kmsClient.Close()

	resp, err := kmsClient.Encrypt(
		ctx,
		&kmsv1.EncryptRequest{
			Name: getKmsName(
				project,
				location,
				keyring,
				key,
			),
			Plaintext:                         data,
			AdditionalAuthenticatedData:       nil,
			PlaintextCrc32C:                   wrapperspb.Int64(int64(crc32Sum(data))),
			AdditionalAuthenticatedDataCrc32C: nil,
		},
	)
	if err != nil {
		err := fmt.Errorf("could not kms encrypt input: %w", err)
		return nil, err
	}

	return resp.Ciphertext, nil
}

// DecryptWithKms decrypts input data using Google KMS. You must have a service account
// referenced by env. var. GOOGLE_APPLICATION_CREDENTIALS
func DecryptWithKms(ctx context.Context,
	data []byte, project, location, keyring, key string) ([]byte, error) {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		err := fmt.Errorf("failed to create kms client: %w", err)
		return nil, err
	}
	defer kmsClient.Close()

	resp, err := kmsClient.Decrypt(
		ctx,
		&kmsv1.DecryptRequest{
			Name: getKmsName(
				project,
				location,
				keyring,
				key,
			),
			Ciphertext:                        data,
			AdditionalAuthenticatedData:       nil,
			CiphertextCrc32C:                  wrapperspb.Int64(int64(crc32Sum(data))),
			AdditionalAuthenticatedDataCrc32C: nil,
		},
	)
	if err != nil {
		err := fmt.Errorf("could not kms decrypt input: %w", err)
		return nil, err
	}

	return resp.Plaintext, nil
}

// getKmsName constructs the canonical URI endpoint path for KMS encryption call
func getKmsName(projectId, kmsLocation, keyringName, keyName string) string {
	return fmt.Sprintf(
		"projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectId,
		kmsLocation,
		keyringName,
		keyName,
	)
}

// crc32Sum produces crc32 sum
func crc32Sum(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

// block is a block of data transaction that carries error
// with it. such blocks are sent on channels to communicate
// between various go routines
type block struct {
	data []byte
	err  error
}

// writeBlock gets called in a synchronized go routine since the intent
// is to write to the writer one block at a time and that too in specific
// sequence. The function first waits on the wait channel and ensures there
// was no upstream error, then performs its duties and writes any error
// on the output channel
func writeBlock(wait <-chan error, c <-chan *block, w io.Writer) chan error {
	waitNext := make(chan error)
	var err error

	go func() {
		defer func() { waitNext <- err }()

		// wait for input wait
		if e := <-wait; e != nil {
			err = e
			return
		}

		b := <-c
		if b.err != nil {
			err = b.err
			return
		}

		if _, e := w.Write(b.data); e != nil {
			err = e
			return
		}
	}()

	return waitNext
}

// decryptBlock decrypts data block. each data block is a json block
// serialized version of EncryptedBlock that has its own data encryption
// key in it. Such key is first decrypted using the input private key,
// then the data is decrypted using decrypted data encryption key and
// returned on the channel of block.
func decryptBlock(data []byte, priv *rsa.PrivateKey) <-chan *block {
	c := make(chan *block)
	b := &block{}

	go func() {
		defer func() { c <- b }()

		eb := &EncryptedBlock{}
		if err := json.Unmarshal(data, eb); err != nil {
			b.err = err
			return
		}

		key, err := DecryptWithPrivateKey(eb.DataEncryptionKey, priv)
		if err != nil {
			b.err = err
			return
		}

		data, err := DecryptWithAesKey(eb.Ciphertext, key)
		if err != nil {
			b.err = err
			return
		}

		b.data = data
		return
	}()

	return c
}

// encryptBlock encrypts data using a symmetric AES key. such key is
// generated on the fly to encrypt the data. data encryption key is
// then encrypted using asymmetric input public key and stored next
// to the data. The output is then serialized in a json format and
// sent on the output channel
func encryptBlock(data []byte, pub *rsa.PublicKey) <-chan *block {
	c := make(chan *block)
	b := &block{}

	go func() {
		defer func() { c <- b }()

		key, err := NewAesKey()
		if err != nil {
			b.err = err
			return
		}

		ciphertext, err := EncryptWithAesKey(data, key)
		if err != nil {
			b.err = err
			return
		}

		dek, err := EncryptWithPublicKey(key, pub)
		if err != nil {
			b.err = err
			return
		}

		eb := &EncryptedBlock{
			DataEncryptionKey: dek,
			Ciphertext:        ciphertext,
		}

		jb, err := eb.Marshal()
		if err != nil {
			b.err = err
			return
		}

		b.data = append(jb, '\n')
	}()

	return c
}
