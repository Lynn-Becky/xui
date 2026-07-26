package web

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"x-ui/web/controller"

	"github.com/gin-gonic/gin"
)

// parseProbeTemplate builds a tiny template set that renders one translated
// string, so the tests exercise locale selection without depending on the
// panel's real pages.
func parseProbeTemplate(funcMap template.FuncMap) (*template.Template, error) {
	return template.New("").Funcs(funcMap).Parse(`{{define "probe.html"}}{{ i18n "login" }}{{end}}`)
}

func newProbeRenderer(t *testing.T) *localeRenderer {
	t.Helper()
	renderer, err := newLocaleRenderer(parseProbeTemplate)
	if err != nil {
		t.Fatalf("newLocaleRenderer() error = %v", err)
	}
	return renderer
}

func TestLocaleRendererBuildsASetPerTranslatedLocale(t *testing.T) {
	renderer := newProbeRenderer(t)

	if len(renderer.sets) < 2 {
		t.Fatalf("built %d template sets, want one per translation file", len(renderer.sets))
	}
	if renderer.fallback == nil {
		t.Fatal("renderer has no fallback template set")
	}
	// The project default must be the fallback, so a client that sends no
	// Accept-Language still gets Chinese.
	if got := renderer.Resolve(""); !strings.HasPrefix(got, "zh") {
		t.Errorf("Resolve(\"\") = %q, want the zh fallback", got)
	}
}

func TestLocaleRendererResolve(t *testing.T) {
	renderer := newProbeRenderer(t)

	for _, tc := range []struct {
		accept string
		want   string
	}{
		{"en-US,en;q=0.9", "en"},
		{"en", "en"},
		{"zh-CN,zh;q=0.9", "zh"},
		{"", "zh"},
		{"not a valid header ///", "zh"},
		{"xx-YY", "zh"},
	} {
		got := renderer.Resolve(tc.accept)
		if !strings.HasPrefix(got, tc.want) {
			t.Errorf("Resolve(%q) = %q, want a %q locale", tc.accept, got, tc.want)
		}
	}
}

func renderWithLocale(t *testing.T, engine *gin.Engine, accept string) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/probe", nil)
	if accept != "" {
		request.Header.Set("Accept-Language", accept)
	}
	engine.ServeHTTP(recorder, request)
	return recorder.Body.String()
}

func newProbeEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	renderer := newProbeRenderer(t)

	engine := gin.New()
	engine.HTMLRender = renderer
	engine.Use(func(c *gin.Context) {
		c.Set(controller.LocaleKey, renderer.Resolve(c.GetHeader("Accept-Language")))
	})
	engine.GET("/probe", func(c *gin.Context) {
		c.HTML(http.StatusOK, "probe.html", gin.H{controller.LocaleKey: c.GetString(controller.LocaleKey)})
	})
	return engine
}

func TestRenderUsesTheRequestedLocale(t *testing.T) {
	engine := newProbeEngine(t)

	if got := renderWithLocale(t, engine, "en-US"); got != "Log In" {
		t.Errorf("en-US render = %q, want %q", got, "Log In")
	}
	if got := renderWithLocale(t, engine, "zh-CN"); got != "登录" {
		t.Errorf("zh-CN render = %q, want %q", got, "登录")
	}
}

// Regression test for the cross-request language bleed.
//
// The i18n template function previously read a package-level localizer that
// every request overwrote, so a page could render in whichever language another
// concurrent request had asked for — a data race as well as a visible bug. Each
// response must now match the locale its own request asked for.
func TestConcurrentRendersDoNotLeakLocale(t *testing.T) {
	engine := newProbeEngine(t)

	cases := []struct{ accept, want string }{
		{"en-US", "Log In"},
		{"zh-CN", "登录"},
	}

	var wg sync.WaitGroup
	errs := make(chan string, 400)
	for i := 0; i < 200; i++ {
		tc := cases[i%len(cases)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := renderWithLocale(t, engine, tc.accept); got != tc.want {
				errs <- "Accept-Language " + tc.accept + " rendered " + got + ", want " + tc.want
			}
		}()
	}
	wg.Wait()
	close(errs)

	for msg := range errs {
		t.Error(msg)
		return
	}
}
