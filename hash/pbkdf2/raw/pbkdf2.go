package raw

import (
	"hash"
	"math"
	"strconv"

	"golang.org/x/crypto/pbkdf2"
)

const (
	MinRounds = 1
)

var (
	MaxRounds int
)

func Hash(password, salt []byte, rounds int, hf func() hash.Hash) (hash string) {
	return Base64Encode(pbkdf2.Key(password, salt, rounds, hf().Size(), hf))
}

func init() {
	if strconv.IntSize == 4 {
		MaxRounds = math.MaxInt32
	} else {
		MaxRounds = math.MaxInt64
	}
}
