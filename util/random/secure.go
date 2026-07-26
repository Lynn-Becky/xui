package random

import (
	"crypto/rand"
	"math/big"
)

// SecureSeq returns a random alphanumeric string of length n drawn from a
// cryptographically secure source.
//
// Seq is backed by math/rand and must never be used for values that have to be
// unguessable (session keys, bootstrap passwords, tokens) — use this instead.
func SecureSeq(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	runes := make([]rune, n)
	limit := big.NewInt(int64(len(allSeq)))
	for i := 0; i < n; i++ {
		index, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", err
		}
		runes[i] = allSeq[index.Int64()]
	}
	return string(runes), nil
}

// SecureBytes returns n cryptographically secure random bytes.
func SecureBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
