package raw

import (
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const (
	MinRounds = 1
)

func Hash(password, salt []byte, rounds int, hf func() hash.Hash) (hash string) {
	return Base64Encode(pbkdf2.Key(password, salt, rounds, hf().Size(), hf))
}
