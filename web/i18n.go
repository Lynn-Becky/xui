package web

import (
	"html/template"
	"io/fs"
	"x-ui/util/common"
	"x-ui/web/controller"

	"github.com/BurntSushi/toml"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/render"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

// projectDefaultLanguage decides which locale becomes the fallback when the
// client sends no usable Accept-Language header.
var projectDefaultLanguage = language.SimplifiedChinese

// localeRenderer holds one fully parsed template set per translated locale.
//
// html/template functions receive no request context, so the previous
// implementation kept the active localizer in a variable that every request
// overwrote and the shared "i18n" template function read. That is a genuine data
// race, and under concurrent load it rendered pages in whichever language the
// most recently arrived request asked for. Binding a localizer into its own
// template set at startup removes the shared mutable state entirely; there are
// only a couple of locales, so the extra parse is negligible.
type localeRenderer struct {
	sets     map[string]*template.Template
	fallback *template.Template
	tags     []language.Tag
	matcher  language.Matcher
}

// Instance implements render.HTMLRender.
func (r *localeRenderer) Instance(name string, data any) render.Render {
	tmpl := r.fallback
	if h, ok := data.(gin.H); ok {
		if locale, ok := h[controller.LocaleKey].(string); ok {
			if set := r.sets[locale]; set != nil {
				tmpl = set
			}
		}
	}
	return render.HTML{Template: tmpl, Name: name, Data: data}
}

// Resolve maps an Accept-Language header onto one of the available locales.
func (r *localeRenderer) Resolve(accept string) string {
	fallback := r.tags[0].String()
	if accept == "" {
		return fallback
	}
	desired, _, err := language.ParseAcceptLanguage(accept)
	if err != nil || len(desired) == 0 {
		return fallback
	}
	_, index, _ := r.matcher.Match(desired...)
	if index < 0 || index >= len(r.tags) {
		return fallback
	}
	return r.tags[index].String()
}

// findI18nParamNames extracts the {{.Name}} placeholders from a message id so
// positional arguments can be bound to them.
func findI18nParamNames(key string) []string {
	names := make([]string, 0)
	keyLen := len(key)
	for i := 0; i < keyLen-1; i++ {
		if key[i:i+2] == "{{" { // 判断开头 "{{"
			j := i + 2
			isFind := false
			for ; j < keyLen-1; j++ {
				if key[j:j+2] == "}}" { // 结尾 "}}"
					isFind = true
					break
				}
			}
			if isFind {
				names = append(names, key[i+3:j])
			}
		}
	}
	return names
}

// i18nFunc builds the template "i18n" function bound to a single localizer.
func i18nFunc(localizer *i18n.Localizer) func(string, ...string) (string, error) {
	return func(key string, params ...string) (string, error) {
		names := findI18nParamNames(key)
		if len(names) != len(params) {
			return "", common.NewError("find names:", names, "---------- params:", params, "---------- num not equal")
		}
		templateData := map[string]interface{}{}
		for i := range names {
			templateData[names[i]] = params[i]
		}
		return localizer.Localize(&i18n.LocalizeConfig{
			MessageID:    key,
			TemplateData: templateData,
		})
	}
}

// loadTranslationBundle reads the embedded translation files and reports the
// tags that actually have messages. Only those get a template set, so no
// localizer is ever built for a language with no catalogue behind it.
func loadTranslationBundle() (*i18n.Bundle, []language.Tag, error) {
	bundle := i18n.NewBundle(projectDefaultLanguage)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)

	tags := make([]language.Tag, 0, 4)
	err := fs.WalkDir(i18nFS, "translation", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := i18nFS.ReadFile(path)
		if err != nil {
			return err
		}
		messageFile, err := bundle.ParseMessageFileBytes(data, path)
		if err != nil {
			return err
		}
		tags = append(tags, messageFile.Tag)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	if len(tags) == 0 {
		return nil, nil, common.NewError("no translation files were loaded")
	}
	return bundle, tags, nil
}

// newLocaleRenderer parses one template set per translated locale. parse is
// called once per locale with that locale's function map.
func newLocaleRenderer(parse func(template.FuncMap) (*template.Template, error)) (*localeRenderer, error) {
	bundle, tags, err := loadTranslationBundle()
	if err != nil {
		return nil, err
	}

	// Move the project default to the front so it becomes the fallback set.
	if index := bestMatchIndex(tags, projectDefaultLanguage); index > 0 {
		tags[0], tags[index] = tags[index], tags[0]
	}

	r := &localeRenderer{
		sets:    make(map[string]*template.Template, len(tags)),
		tags:    tags,
		matcher: language.NewMatcher(tags),
	}
	for _, tag := range tags {
		set, err := parse(template.FuncMap{"i18n": i18nFunc(i18n.NewLocalizer(bundle, tag.String()))})
		if err != nil {
			return nil, err
		}
		r.sets[tag.String()] = set
	}
	r.fallback = r.sets[tags[0].String()]
	return r, nil
}

func bestMatchIndex(tags []language.Tag, want language.Tag) int {
	_, index, _ := language.NewMatcher(tags).Match(want)
	if index < 0 || index >= len(tags) {
		return 0
	}
	return index
}
