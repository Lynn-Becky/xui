package session

import (
	"crypto/sha256"
	"io"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"golang.org/x/crypto/hkdf"
)

// TokenLifetime caps how long a signed session cookie stays verifiable.
//
// Sessions are additionally revoked server-side whenever the credentials change
// (see the fingerprint carried in LoginSession); this bound is the backstop for
// a token that leaked without the password being rotated. gorilla's default is
// 30 days.
const TokenLifetime = 7 * 24 * time.Hour

// DeriveKeys splits the stored panel secret into an independent authentication
// key and an AES-256 encryption key.
//
// cookie.NewStore treats its arguments as (hashKey, blockKey) pairs, so passing
// a single key leaves blockKey nil and securecookie then signs the session
// without encrypting it — everything stored in the session becomes readable by
// anyone holding the cookie. Deriving both keys makes the cookie confidential as
// well as tamper-proof, and HKDF accepts the existing stored secret unchanged so
// no migration is required.
func DeriveKeys(secret []byte) (authKey, encKey []byte, err error) {
	derive := func(info string) ([]byte, error) {
		key := make([]byte, 32)
		if _, err := io.ReadFull(hkdf.New(sha256.New, secret, nil, []byte(info)), key); err != nil {
			return nil, err
		}
		return key, nil
	}
	if authKey, err = derive("x-ui session authentication key"); err != nil {
		return nil, nil, err
	}
	if encKey, err = derive("x-ui session encryption key"); err != nil {
		return nil, nil, err
	}
	return authKey, encKey, nil
}

// NewStore builds the panel's session store: encrypted, HttpOnly, scoped to the
// panel base path, and with a bounded token lifetime.
//
// secure should be true only when the panel terminates TLS itself; marking the
// cookie Secure over plain HTTP would stop the browser from ever sending it.
func NewStore(secret []byte, basePath string, secure bool) (sessions.Store, error) {
	authKey, encKey, err := DeriveKeys(secret)
	if err != nil {
		return nil, err
	}
	store := cookie.NewStore(authKey, encKey)

	// Order matters. MaxAge writes both the cookie options and every codec's
	// expiry, whereas Options replaces the options struct only. Calling MaxAge
	// first and Options second therefore bounds how long a token verifies while
	// still leaving the browser cookie a session cookie that dies on close.
	if bounded, ok := store.(interface{ MaxAge(int) }); ok {
		bounded.MaxAge(int(TokenLifetime / time.Second))
	}
	store.Options(sessions.Options{
		Path:     basePath,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return store, nil
}
