package session

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func TestDeriveKeys(t *testing.T) {
	secret := []byte("a-stored-panel-secret")

	authKey, encKey, err := DeriveKeys(secret)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	if len(authKey) != 32 {
		t.Errorf("len(authKey) = %d, want 32", len(authKey))
	}
	// Must be 16, 24 or 32 bytes for securecookie to select an AES mode.
	if len(encKey) != 32 {
		t.Errorf("len(encKey) = %d, want 32", len(encKey))
	}
	if bytes.Equal(authKey, encKey) {
		t.Error("authentication and encryption keys are identical")
	}

	againAuth, againEnc, err := DeriveKeys(secret)
	if err != nil {
		t.Fatalf("DeriveKeys() second call error = %v", err)
	}
	if !bytes.Equal(authKey, againAuth) || !bytes.Equal(encKey, againEnc) {
		t.Error("DeriveKeys() is not deterministic for the same secret")
	}

	otherAuth, _, err := DeriveKeys([]byte("a-different-secret"))
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	if bytes.Equal(authKey, otherAuth) {
		t.Error("different secrets produced the same authentication key")
	}
}

// cookiePayload returns the inner, post-base64 session bytes that anyone holding
// the cookie can recover without possessing any key.
func cookiePayload(t *testing.T, value string) []byte {
	t.Helper()
	outer, err := base64.URLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}
	// securecookie emits base64( date | base64(payload) | mac ).
	parts := bytes.Split(outer, []byte("|"))
	if len(parts) != 3 {
		t.Fatalf("got %d cookie segments, want 3", len(parts))
	}
	inner, err := base64.URLEncoding.DecodeString(string(parts[1]))
	if err != nil {
		t.Fatalf("decode cookie payload: %v", err)
	}
	return inner
}

func issueSessionCookie(t *testing.T, store sessions.Store, marker string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("session", store))
	router.GET("/seed", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("value", marker)
		if err := s.Save(); err != nil {
			t.Errorf("save session: %v", err)
		}
	})

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://example.test/seed", nil))
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	return cookies[0].Value
}

// Regression test for the session cookie disclosing its own contents.
//
// A store built from a single key only signs the session, so whatever it holds
// can be read back by base64-decoding the cookie. The panel used to keep the
// entire user record — including the administrator's cleartext password — in
// there. Deriving a separate encryption key is what closes that.
func TestNewStoreEncryptsSessionContents(t *testing.T) {
	const marker = "a-value-that-must-not-be-readable"
	secret := []byte("a-stored-panel-secret")

	store, err := NewStore(secret, "/panel/", true)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	if payload := cookiePayload(t, issueSessionCookie(t, store, marker)); bytes.Contains(payload, []byte(marker)) {
		t.Fatalf("session contents are readable from the cookie without a key: %q", payload)
	}

	// Confirm the assertion above can actually fail: the single-key store the
	// panel used before is signed only, and the marker is plainly visible.
	authKey, _, err := DeriveKeys(secret)
	if err != nil {
		t.Fatalf("DeriveKeys() error = %v", err)
	}
	signedOnly := issueSessionCookie(t, cookie.NewStore(authKey), marker)
	if payload := cookiePayload(t, signedOnly); !bytes.Contains(payload, []byte(marker)) {
		t.Fatal("single-key store unexpectedly hid the session contents; this test no longer proves anything")
	}
}

func TestNewStoreCookieAttributes(t *testing.T) {
	store, err := NewStore([]byte("a-stored-panel-secret"), "/panel/", true)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("session", store))
	router.GET("/seed", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("value", "x")
		if err := s.Save(); err != nil {
			t.Errorf("save session: %v", err)
		}
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://example.test/seed", nil))

	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want 1", len(cookies))
	}
	got := cookies[0]
	if !got.HttpOnly {
		t.Error("cookie is not HttpOnly")
	}
	if !got.Secure {
		t.Error("cookie is not Secure when the panel terminates TLS")
	}
	if got.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", got.SameSite)
	}
	if got.Path != "/panel/" {
		t.Errorf("Path = %q, want /panel/", got.Path)
	}
	// A session cookie, so closing the browser drops it. MaxAge bounds the
	// signed token instead; see TokenLifetime.
	if got.MaxAge != 0 {
		t.Errorf("MaxAge = %d, want 0 (session cookie)", got.MaxAge)
	}
}
