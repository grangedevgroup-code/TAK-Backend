package web

import (
	"encoding/json"
	"io/fs"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestTranslations(t *testing.T) {
	app, err := fs.ReadFile(Assets(), "app.js")
	if err != nil {
		t.Fatal(err)
	}
	place := regexp.MustCompile(`\{[nx]\}`)
	files, _ := fs.Glob(Assets(), "i18n/*.json")
	if len(files) == 0 {
		t.Fatal("no translations")
	}
	for _, f := range files {
		lang := strings.TrimSuffix(strings.TrimPrefix(f, "i18n/"), ".json")
		if !strings.Contains(string(app), `["`+lang+`", `) {
			t.Errorf("%s is not offered in the language list", lang)
		}
		b, _ := fs.ReadFile(Assets(), f)
		var dict map[string]string
		if err := json.Unmarshal(b, &dict); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for k, v := range dict {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: empty translation for %q", f, k)
			}
			if !slices.Equal(place.FindAllString(k, -1), place.FindAllString(v, -1)) {
				t.Errorf("%s: placeholders differ in %q -> %q", f, k, v)
			}
		}
	}
}
