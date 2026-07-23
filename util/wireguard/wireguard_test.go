package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestGenerateAndValidateKeypair(t *testing.T) {
	privateKey, publicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeypair(privateKey, publicKey); err != nil {
		t.Fatalf("generated keypair rejected: %v", err)
	}
	derived, err := PublicKeyFromPrivate(privateKey)
	if err != nil || derived != publicKey {
		t.Fatalf("public key derivation = %q, %v; want %q", derived, err, publicKey)
	}

	raw, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PublicKeyFromPrivate(hex.EncodeToString(raw)); err != nil {
		t.Fatalf("hexadecimal private key rejected: %v", err)
	}
}

func TestValidateKeypairRejectsMismatch(t *testing.T) {
	privateKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, otherPublicKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeypair(privateKey, otherPublicKey); err == nil {
		t.Fatal("mismatched keypair accepted")
	}
	if err := ValidateKeypair("not-a-key", otherPublicKey); err == nil {
		t.Fatal("malformed private key accepted")
	}
}
