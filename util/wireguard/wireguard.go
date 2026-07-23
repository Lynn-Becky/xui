package wireguard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// GenerateKeypair returns a WireGuard Curve25519 keypair in standard base64.
func GenerateKeypair() (privateKey, publicKey string, err error) {
	var private [32]byte
	if _, err = rand.Read(private[:]); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)
	return base64.StdEncoding.EncodeToString(private[:]), base64.StdEncoding.EncodeToString(public[:]), nil
}

// PublicKeyFromPrivate derives the standard-base64 public key from a base64
// or hexadecimal private key.
func PublicKeyFromPrivate(privateKey string) (string, error) {
	private, err := decodeKey(privateKey)
	if err != nil {
		return "", err
	}
	var public [32]byte
	curve25519.ScalarBaseMult(&public, &private)
	return base64.StdEncoding.EncodeToString(public[:]), nil
}

// ValidateKeypair verifies both key encodings and their Curve25519 relation.
func ValidateKeypair(privateKey, publicKey string) error {
	private, err := decodeKey(privateKey)
	if err != nil {
		return errors.New("invalid WireGuard private key")
	}
	provided, err := decodeKey(publicKey)
	if err != nil {
		return errors.New("invalid WireGuard public key")
	}
	var derived [32]byte
	curve25519.ScalarBaseMult(&derived, &private)
	if subtle.ConstantTimeCompare(derived[:], provided[:]) != 1 {
		return errors.New("WireGuard public key does not match private key")
	}
	return nil
}

func decodeKey(key string) ([32]byte, error) {
	var result [32]byte
	if key == "" || key != strings.TrimSpace(key) {
		return result, errors.New("WireGuard key is empty or contains whitespace")
	}
	if len(key) == 64 {
		if decoded, err := hex.DecodeString(key); err == nil && len(decoded) == len(result) {
			copy(result[:], decoded)
			return result, nil
		}
	}

	trimmed := strings.TrimRight(key, "=")
	for _, encoding := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(trimmed)
		if err == nil && len(decoded) == len(result) {
			copy(result[:], decoded)
			return result, nil
		}
	}
	return result, errors.New("WireGuard key must decode to 32 bytes")
}
