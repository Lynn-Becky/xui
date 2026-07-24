package tests

import (
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"testing"
)

func TestHTMLTemplatesParse(t *testing.T) {
	root := filepath.Join("..", "web", "html")
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && filepath.Ext(path) == ".html" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = template.New("").Funcs(template.FuncMap{
		"i18n": func(string, ...string) string { return "" },
	}).ParseFiles(files...)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInboundTransportOptionsMatch3xUI(t *testing.T) {
	path := filepath.Join("..", "web", "html", "xui", "form", "stream", "stream_settings.html")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`<a-select-option value="([^"]+)">([^<]+)</a-select-option>`)
	matches := re.FindAllStringSubmatch(string(content), -1)
	got := make([][2]string, 0, len(matches))
	for _, match := range matches {
		got = append(got, [2]string{match[1], match[2]})
	}
	want := [][2]string{
		{"tcp", "RAW"},
		{"kcp", "mKCP"},
		{"ws", "WebSocket"},
		{"grpc", "gRPC"},
		{"httpupgrade", "HTTPUpgrade"},
		{"xhttp", "XHTTP"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("transport options = %#v, want %#v", got, want)
	}
}
