package crypto

import (
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/corpix/gdk/errors"
)

// see: https://leanpub.com/gocrypto/read#leanpub-auto-nacl

const (
	SecretBoxKeySize   = 32
	SecretBoxNonceSize = 24
	SecretBoxOverhead  = secretbox.Overhead
)

type (
	SecretBoxKey   = [SecretBoxKeySize]byte
	SecretBoxNonce = [SecretBoxNonceSize]byte
)

//

type SecretBox struct {
	rand Rand
	key  *SecretBoxKey
}

func (s *SecretBox) Nonce() (*SecretBoxNonce, error) {
	return SecretBoxNonceGen(s.rand)
}

func (s *SecretBox) Seal(nonce *SecretBoxNonce, message []byte) []byte {
	return SecretBoxSeal(s.key, nonce, message)
}

func (s *SecretBox) SealBase64(nonce *SecretBoxNonce, message []byte) []byte {
	return SecretBoxSealBase64(s.key, nonce, message)
}

func (s *SecretBox) Open(box []byte) ([]byte, error) {
	return SecretBoxOpen(s.key, box)
}

func (s *SecretBox) OpenBase64(box []byte) ([]byte, error) {
	return SecretBoxOpenBase64(s.key, box)
}

func (s *SecretBox) Rand() Rand {
	return s.rand
}

//

func SecretBoxKeyGen(rand Rand) (*SecretBoxKey, error) {
	key := new(SecretBoxKey)
	_, err := io.ReadFull(rand, key[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read key bytes from entropy source")
	}

	return key, nil
}

func SecretBoxKeyDerive(rand Rand, key *SecretBoxKey) (*SecretBoxKey, error) {
	salt := make([]byte, SecretBoxKeySize)

	_, err := io.ReadFull(rand, salt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read salt bytes from entropy source")
	}

	// salt size == key size
	// 8 passes over 128KiB on 2 threads
	derivedKey := argon2.Key(key[:], salt, 8, 128, 2, SecretBoxKeySize)
	buf := new(SecretBoxKey)
	copy(buf[:], derivedKey)

	return buf, nil
}

func SecretBoxNonceGen(rand Rand) (*SecretBoxNonce, error) {
	nonce := new(SecretBoxNonce)
	_, err := io.ReadFull(rand, nonce[:])
	if err != nil {
		return nil, errors.Wrap(err, "failed to read nonce bytes from entropy source")
	}

	return nonce, nil
}

func SecretBoxSeal(key *SecretBoxKey, nonce *SecretBoxNonce, message []byte) []byte {
	box := make([]byte, SecretBoxNonceSize)
	copy(box, nonce[:])
	return secretbox.Seal(box, message, nonce, key)
}

func SecretBoxSealBase64(key *SecretBoxKey, nonce *SecretBoxNonce, message []byte) []byte {
	box := SecretBoxSeal(key, nonce, message)
	base64Box := make([]byte, base64.RawStdEncoding.EncodedLen(len(box)))
	base64.RawStdEncoding.Encode(base64Box, box)
	return base64Box
}

func SecretBoxOpen(key *SecretBoxKey, box []byte) ([]byte, error) {
	if len(box) < (SecretBoxNonceSize + SecretBoxOverhead) {
		return nil, ErrFormat{
			Msg: fmt.Sprintf(
				"illformed encrypted message, expected message size to be at least %d, got: %d",
				(SecretBoxNonceSize + SecretBoxOverhead), len(box),
			),
		}
	}

	var nonce SecretBoxNonce
	copy(nonce[:], box[:SecretBoxNonceSize])

	message, ok := secretbox.Open(nil, box[SecretBoxNonceSize:], &nonce, key)
	if !ok {
		return nil, ErrDecrypt{Msg: "failed to decrypt message"}
	}

	return message, nil
}

func SecretBoxOpenBase64(key *SecretBoxKey, box []byte) ([]byte, error) {
	buf := make([]byte, base64.RawStdEncoding.DecodedLen(len(box)))
	_, err := base64.RawStdEncoding.Decode(buf, box)
	if err != nil {
		return nil, err
	}
	return SecretBoxOpen(key, buf)
}

//

func NewSecretBox(rand Rand, key *SecretBoxKey) *SecretBox {
	return &SecretBox{
		rand: rand,
		key:  key,
	}
}
