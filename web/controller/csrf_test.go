package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"x-ui/web/session"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func newCSRFRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	store, err := session.NewStore([]byte("test-secret"), "/", false)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	base := &BaseController{}
	router := gin.New()
	router.Use(sessions.Sessions("session", store))
	router.Use(base.checkCSRF)
	router.GET("/page", func(c *gin.Context) {
		// Mirrors what html() publishes to the template.
		c.String(http.StatusOK, c.GetString(CSRFTokenKey))
	})
	router.POST("/change", func(c *gin.Context) {
		c.String(http.StatusOK, "changed")
	})
	return router
}

// issueToken performs the initial GET and returns the published token plus the
// session cookie needed to keep using it.
func issueToken(t *testing.T, router *gin.Engine) (string, *http.Cookie) {
	t.Helper()
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/page", nil))

	token := recorder.Body.String()
	if token == "" {
		t.Fatal("no CSRF token was published to the page")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies, want the session cookie", len(cookies))
	}
	return token, cookies[0]
}

func postChange(t *testing.T, router *gin.Engine, cookie *http.Cookie, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/change", nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	if token != "" {
		request.Header.Set(csrfHeader, token)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

// succeeded reports whether the handler ran. The panel answers rejections with
// HTTP 200 and success=false rather than a 4xx, so the status alone is not
// enough to tell the two apart.
func succeeded(t *testing.T, recorder *httptest.ResponseRecorder) bool {
	t.Helper()
	if recorder.Body.String() == "changed" {
		return true
	}
	var msg struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &msg); err != nil {
		t.Fatalf("unexpected response body %q: %v", recorder.Body.String(), err)
	}
	return msg.Success
}

func TestCSRFPublishesTokenOnSafeMethods(t *testing.T) {
	router := newCSRFRouter(t)
	token, cookie := issueToken(t, router)

	if len(token) < 16 {
		t.Errorf("token %q is shorter than expected", token)
	}
	if !cookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
}

func TestCSRFAcceptsMatchingToken(t *testing.T) {
	router := newCSRFRouter(t)
	token, cookie := issueToken(t, router)

	if !succeeded(t, postChange(t, router, cookie, token)) {
		t.Fatal("a request carrying the correct token was rejected")
	}
}

func TestCSRFRejectsMissingOrWrongToken(t *testing.T) {
	router := newCSRFRouter(t)
	token, cookie := issueToken(t, router)

	for name, tc := range map[string]struct {
		cookie *http.Cookie
		token  string
	}{
		"no token at all":            {cookie, ""},
		"wrong token":                {cookie, "not-the-right-token-value-here"},
		"token from another session": {nil, token},
		"session but no header":      {cookie, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if succeeded(t, postChange(t, router, tc.cookie, tc.token)) {
				t.Fatal("a state-changing request was accepted without a valid token")
			}
		})
	}
}

// The token must be stable for the life of the session, otherwise every page in
// an open tab would stop being able to submit.
func TestCSRFTokenIsStableAcrossRequests(t *testing.T) {
	router := newCSRFRouter(t)
	token, cookie := issueToken(t, router)

	request := httptest.NewRequest(http.MethodGet, "/page", nil)
	request.AddCookie(cookie)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if got := recorder.Body.String(); got != token {
		t.Fatalf("token changed between requests: %q then %q", token, got)
	}
}
