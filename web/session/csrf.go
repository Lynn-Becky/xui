package session

import (
	"x-ui/util/random"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const csrfToken = "CSRF_TOKEN"

// EnsureCSRFToken returns the session's CSRF token, minting and persisting one
// on first use.
//
// The token is a synchronizer token: it lives in the session and must be echoed
// back in a request header, which an attacker's page cannot read cross-origin.
// SameSite=Lax alone is not sufficient here because "site" ignores the port, so
// any other HTTP service on the same host — including one the panel's own Xray
// serves — counts as same-site and can issue cookie-bearing cross-origin
// requests.
func EnsureCSRFToken(c *gin.Context) (string, error) {
	s := sessions.Default(c)
	if existing, ok := s.Get(csrfToken).(string); ok && existing != "" {
		return existing, nil
	}
	token, err := random.SecureSeq(32)
	if err != nil {
		return "", err
	}
	s.Set(csrfToken, token)
	if err := s.Save(); err != nil {
		return "", err
	}
	return token, nil
}
