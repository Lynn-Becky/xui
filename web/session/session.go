package session

import (
	"encoding/gob"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	loginUser = "LOGIN_USER"
)

// LoginSession is the entire contents of the session cookie.
//
// It deliberately carries no credential material. Earlier versions stored the
// whole user record here, which put the administrator's password into the
// cookie — and because a single-key cookie store only signs (it does not
// encrypt), that password was recoverable by base64-decoding the cookie. Only
// values that are safe to disclose may be added to this struct.
//
// Fingerprint pins the session to the username/password it was issued against;
// see (*model.User).CredentialFingerprint.
type LoginSession struct {
	UserId      int
	Fingerprint string
}

func init() {
	gob.Register(LoginSession{})
}

// SetLoginSession issues a session for the given account. Callers pass
// user.CredentialFingerprint() so the cookie stops resolving once the
// credentials change.
func SetLoginSession(c *gin.Context, userId int, fingerprint string) error {
	s := sessions.Default(c)
	s.Set(loginUser, LoginSession{UserId: userId, Fingerprint: fingerprint})
	return s.Save()
}

// GetLoginSession returns the raw session contents, or nil when there is no
// usable session. A non-nil result only means the cookie was well formed and
// correctly signed — the caller must still resolve the user and check the
// fingerprint before treating the request as authenticated.
func GetLoginSession(c *gin.Context) *LoginSession {
	s := sessions.Default(c)
	obj := s.Get(loginUser)
	if obj == nil {
		return nil
	}
	value, ok := obj.(LoginSession)
	if !ok {
		return nil
	}
	if value.UserId <= 0 || value.Fingerprint == "" {
		return nil
	}
	return &value
}

func ClearSession(c *gin.Context) {
	s := sessions.Default(c)
	s.Clear()
	cookiePath := c.GetString("base_path")
	if cookiePath == "" {
		cookiePath = "/"
	}
	directHTTPS, _ := c.Get("direct_https")
	secure, _ := directHTTPS.(bool)
	s.Options(sessions.Options{
		Path:     cookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	_ = s.Save()
}
