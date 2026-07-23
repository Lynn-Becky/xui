package session

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func TestClearSessionUsesBasePathAndClearsLegacyRootCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := cookie.NewStore([]byte("01234567890123456789012345678901"))
	router.Use(sessions.Sessions("session", store))
	router.GET("/login", func(c *gin.Context) {
		s := sessions.Default(c)
		s.Set("existing", true)
		if err := s.Save(); err != nil {
			t.Fatalf("save seed session: %v", err)
		}
	})
	router.GET("/panel/logout", func(c *gin.Context) {
		c.Set("base_path", "/panel/")
		c.Set("direct_https", true)
		ClearSession(c)
	})

	loginRecorder := httptest.NewRecorder()
	router.ServeHTTP(loginRecorder, httptest.NewRequest(http.MethodGet, "https://example.test/login", nil))
	loginCookies := loginRecorder.Result().Cookies()
	if len(loginCookies) != 1 {
		t.Fatalf("got %d seed cookies, want 1", len(loginCookies))
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://example.test/panel/logout", nil)
	request.AddCookie(loginCookies[0])
	router.ServeHTTP(recorder, request)

	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("got %d cookies, want path-scoped and legacy-root clear cookies", len(cookies))
	}
	for _, c := range cookies {
		if c.Name != "session" || c.MaxAge >= 0 || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
			t.Errorf("unexpected cleared cookie: %#v", c)
		}
	}
	if cookies[0].Path != "/panel/" || cookies[1].Path != "/" {
		t.Errorf("cookie paths = %q, %q; want /panel/ then /", cookies[0].Path, cookies[1].Path)
	}
}
