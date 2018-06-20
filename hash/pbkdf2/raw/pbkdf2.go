package raw

import (
	"hash"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

const (
	MinRounds = 1
	MaxRounds = 1<<strconv.IntSize - 1 // setting at 32-bit limit for now
)

func Hash(password, salt []byte, rounds int, hf func() hash.Hash) (hash string) {
	return Base64Encode(pbkdf2.Key(password, salt, rounds, hf().Size(), hf))
}
