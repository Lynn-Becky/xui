package web

import (
	"html/template"
	"testing"
)

func TestEmbeddedHTMLTemplatesParseAndExposeInboundForms(t *testing.T) {
	server := NewServer()
	templates, err := server.getHtmlTemplate(template.FuncMap{
		"i18n": func(string) string { return "" },
	})
	if err != nil {
		t.Fatalf("parse embedded HTML templates: %v", err)
	}

	for _, name := range []string{
		"form/mixed",
		"form/tunnel",
		"form/wireguard",
		"form/hysteria",
		"form/hysteriaStream",
		"form/streamHTTPUpgrade",
		"form/streamXHTTP",
	} {
		if templates.Lookup(name) == nil {
			t.Errorf("missing parsed template %q", name)
		}
	}
}
