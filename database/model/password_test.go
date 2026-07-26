package model

import "testing"

func TestHashPasswordProducesVerifiableHash(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hash == "correct horse battery staple" {
		t.Fatal("HashPassword() returned the cleartext password")
	}
	if !IsHashedPassword(hash) {
		t.Fatal("IsHashedPassword() did not recognise a freshly generated hash")
	}

	ok, needsRehash := VerifyPassword(hash, "correct horse battery staple")
	if !ok {
		t.Fatal("VerifyPassword() rejected the correct password")
	}
	if needsRehash {
		t.Fatal("VerifyPassword() asked to rehash an already hashed row")
	}

	if ok, _ := VerifyPassword(hash, "wrong password"); ok {
		t.Fatal("VerifyPassword() accepted the wrong password")
	}
}

// Rows written before password hashing hold cleartext. They must keep working
// and must report that they should be rewritten, otherwise upgrading the panel
// would lock existing operators out.
func TestVerifyPasswordUpgradesLegacyCleartextRow(t *testing.T) {
	ok, needsRehash := VerifyPassword("admin", "admin")
	if !ok {
		t.Fatal("VerifyPassword() rejected a correct legacy cleartext password")
	}
	if !needsRehash {
		t.Fatal("VerifyPassword() did not flag a legacy cleartext row for rehashing")
	}

	if ok, _ := VerifyPassword("admin", "nope"); ok {
		t.Fatal("VerifyPassword() accepted a wrong password against a legacy row")
	}
}

func TestIsHashedPasswordRejectsCleartext(t *testing.T) {
	for _, value := range []string{"", "admin", "$2a$notreallyahash", "hunter2"} {
		if IsHashedPassword(value) {
			t.Errorf("IsHashedPassword(%q) = true, want false", value)
		}
	}
}

// The session cookie carries only this fingerprint. It must change whenever
// either credential field changes, because that is what makes a password change
// invalidate sessions that were issued against the old credentials.
func TestCredentialFingerprintChangesWithCredentials(t *testing.T) {
	base := &User{Id: 1, Username: "admin", Password: "hash-a"}
	original := base.CredentialFingerprint()

	if original == "" {
		t.Fatal("CredentialFingerprint() returned an empty string")
	}
	if same := (&User{Id: 1, Username: "admin", Password: "hash-a"}).CredentialFingerprint(); same != original {
		t.Fatal("CredentialFingerprint() is not stable for identical credentials")
	}
	if changed := (&User{Id: 1, Username: "admin", Password: "hash-b"}).CredentialFingerprint(); changed == original {
		t.Fatal("CredentialFingerprint() did not change when the password changed")
	}
	if changed := (&User{Id: 1, Username: "root", Password: "hash-a"}).CredentialFingerprint(); changed == original {
		t.Fatal("CredentialFingerprint() did not change when the username changed")
	}

	// A fingerprint must not leak the stored credential it was derived from.
	if original == "hash-a" {
		t.Fatal("CredentialFingerprint() exposed the stored credential")
	}
}
