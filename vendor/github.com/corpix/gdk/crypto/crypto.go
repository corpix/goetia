package crypto

import (
	"crypto"
	"crypto/rand"
	"io"
	"math/big"
)

type (
	Rand      io.Reader
	PublicKey = crypto.PublicKey
)

var DefaultRand = Rand(rand.Reader)

func RandRead(b []byte) (int, error) {
	return DefaultRand.Read(b)
}
func RandInt(max *big.Int) (*big.Int, error) {
	return rand.Int(DefaultRand, max)
}
