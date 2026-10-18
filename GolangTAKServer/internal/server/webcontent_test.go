package server

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestWebContentAndAccessRules(t *testing.T) {
	s := newTestServer(t, func(c *Config) {
		c.Web.ContentAccess = []ContentAccessRule{{Folder: "/secure", Groups: []string{"Red"}}, {Folder: "members"}}
	})
	root := filepath.Join(s.DataDir, "webcontent")
	for p, body := range map[string]string{"public/hello.txt": "hello", "secure/doc.txt": "red only", "members/x.txt": "signed in", "app/index.html": "<h1>app</h1>", "list/a.txt": "a"} {
		os.MkdirAll(filepath.Dir(filepath.Join(root, p)), 0o755)
		os.WriteFile(filepath.Join(root, p), []byte(body), 0o644)
	}
	os.WriteFile(filepath.Join(s.DataDir, "outside.txt"), []byte("secret"), 0o644)
	s.dir.EnsureGroup("Red", "", false)
	s.dir.EnsureGroup("Blue", "", false)
	s.dir.AddUser("reduser", "red-pass-1234", false, []string{"Red"})
	s.dir.AddUser("blueuser", "blue-pass-1234", false, []string{"Blue"})
	get := func(path, user, pass string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", plainURL(s, path), nil)
		if user != "" {
			req.SetBasicAuth(user, pass)
		}
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if st, b := get("/public/hello.txt", "", ""); st != 200 || b != "hello" {
		t.Fatalf("public file %d %q", st, b)
	}
	if st, _ := get("/secure/doc.txt", "", ""); st != http.StatusUnauthorized {
		t.Fatalf("restricted file without sign-in %d", st)
	}
	if st, _ := get("/secure/doc.txt", "blueuser", "blue-pass-1234"); st != http.StatusForbidden {
		t.Fatalf("restricted file, wrong group %d", st)
	}
	if st, b := get("/secure/doc.txt", "reduser", "red-pass-1234"); st != 200 || b != "red only" {
		t.Fatalf("restricted file, right group %d %q", st, b)
	}
	if st, _ := get("/members/x.txt", "", ""); st != http.StatusUnauthorized {
		t.Fatalf("signed-in-only folder %d", st)
	}
	if st, _ := get("/members/x.txt", "blueuser", "blue-pass-1234"); st != 200 {
		t.Fatalf("signed-in-only folder with a user %d", st)
	}
	if st, b := get("/app/", "", ""); st != 200 || b != "<h1>app</h1>" {
		t.Fatalf("index page %d %q", st, b)
	}
	if st, _ := get("/app", "", ""); st != http.StatusMovedPermanently {
		t.Fatalf("folder without slash %d", st)
	}
	if st, _ := get("/list/", "", ""); st != http.StatusNotFound {
		t.Fatalf("directory listing %d", st)
	}
	for _, p := range []string{"/../outside.txt", "/outside.txt", "/public/../../outside.txt", "/%2e%2e/outside.txt"} {
		st, b := get(p, "", "")
		if st == http.StatusTemporaryRedirect || st == http.StatusMovedPermanently {
			st, b = get("/outside.txt", "", "")
		}
		if st != http.StatusNotFound || b == "secret" {
			t.Fatalf("path traversal %s: %d %q", p, st, b)
		}
	}
	if st, _ := get("/Marti/api/version", "", ""); st != 200 {
		t.Fatalf("API still reachable %d", st)
	}
	if st, _ := get("/", "", ""); st != 200 {
		t.Fatalf("dashboard still served %d", st)
	}
}

func TestLocalPathRejectsOffSiteTargets(t *testing.T) {
	for in, want := range map[string]string{"/missions?x=1": "/missions?x=1", "": "/", "//evil.example": "/", `/\evil.example`: "/", "https://evil.example": "/", "/a\r\nSet-Cookie: x": "/", "evil": "/"} {
		if got := localPath(in); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWebContentFolderRedirectStaysLocal(t *testing.T) {
	s := newTestServer(t, nil)
	os.MkdirAll(filepath.Join(s.DataDir, "webcontent", "evil.example"), 0o755)
	os.WriteFile(filepath.Join(s.DataDir, "webcontent", "evil.example", "index.html"), []byte("x"), 0o644)
	c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := c.Get(plainURL(s, "/evil.example"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || resp.Header.Get("Location") != "/evil.example/" {
		t.Fatalf("folder redirect %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	req, _ := http.NewRequest("GET", plainURL(s, "/x"), nil)
	req.URL.Opaque = "/%5Cevil.example"
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("backslash path %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
