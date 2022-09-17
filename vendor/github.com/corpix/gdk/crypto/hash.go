package crypto

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

func Sha1Bytes(buf []byte) []byte {
	h := sha1.New()
	_, _ = h.Write(buf)
	return h.Sum(nil)
}

func Sha1(s string) string {
	return hex.EncodeToString(Sha1Bytes([]byte(s)))
}

//

func Sha256Bytes(buf []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(buf)
	return h.Sum(nil)
}

func Sha256(s string) string {
	return hex.EncodeToString(Sha256Bytes([]byte(s)))
}

//

func Sha512Bytes(buf []byte) []byte {
	h := sha512.New()
	_, _ = h.Write(buf)
	return h.Sum(nil)
}

func Sha512(s string) string {
	return hex.EncodeToString(Sha512Bytes([]byte(s)))
}
