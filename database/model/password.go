package model

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is bcrypt.DefaultCost. Raising it later is safe: existing hashes
// record the cost they were created with, and VerifyPassword reports when a
// stored hash should be rewritten.
const bcryptCost = bcrypt.DefaultCost

// legacyComparisonHash gives CheckUser a hash to compare against when the
// username does not exist, so a missing account costs roughly the same time as
// a wrong password and cannot be distinguished by timing.
var legacyComparisonHash = mustHash("x-ui-nonexistent-account-placeholder")

func mustHash(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		// Only reachable if bcrypt itself is broken; a panic at init is
		// preferable to silently degrading the login comparison.
		panic("bcrypt unavailable: " + err.Error())
	}
	return hash
}

// HashPassword returns a bcrypt hash of password, suitable for storing in
// User.Password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// IsHashedPassword reports whether stored already holds a bcrypt hash. Rows
// written by panel versions before password hashing hold cleartext.
func IsHashedPassword(stored string) bool {
	_, err := bcrypt.Cost([]byte(stored))
	return err == nil
}

// VerifyPassword checks provided against the stored credential.
//
// needsRehash is true when the row still holds a cleartext password that
// verified correctly, so the caller can transparently upgrade it to bcrypt on a
// successful login. This keeps existing installations working across the
// upgrade without asking operators to reset their password.
func VerifyPassword(stored, provided string) (ok bool, needsRehash bool) {
	if IsHashedPassword(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(provided)) == nil, false
	}
	if subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) != 1 {
		return false, false
	}
	return true, true
}

// EqualizeVerifyTiming burns roughly one bcrypt comparison. Call it on paths
// that reject before reaching VerifyPassword (unknown username) so the response
// time does not reveal whether an account exists.
func EqualizeVerifyTiming(provided string) {
	_ = bcrypt.CompareHashAndPassword(legacyComparisonHash, []byte(provided))
}

// CredentialFingerprint derives a stable, non-reversible tag from the account's
// current username and stored credential.
//
// Sessions carry this instead of the credential itself. Because changing either
// field changes the fingerprint, every cookie issued against the old
// credentials stops resolving — which is what makes a password change revoke
// other sessions even though sessions are stored client-side.
func (u *User) CredentialFingerprint() string {
	sum := sha256.Sum256([]byte(u.Username + "\x00" + u.Password))
	return hex.EncodeToString(sum[:])
}
