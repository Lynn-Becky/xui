package tests

import (
	"html/template"
	"io/fs"
	"path/filepath"
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
