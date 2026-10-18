package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestOpenAPIDocument(t *testing.T) {
	s := newTestServer(t, func(c *Config) { c.AllowAnonymous = false })
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/v3/api-docs"), nil, nil); st != http.StatusUnauthorized {
		t.Fatalf("anonymous api-docs status %d", st)
	}
	admin := adminHeaders(t, s)
	st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/v3/api-docs"), nil, admin)
	if st != http.StatusOK {
		t.Fatalf("api-docs %d %s", st, b)
	}
	var doc struct {
		OpenAPI    string                               `json:"openapi"`
		Paths      map[string]map[string]map[string]any `json:"paths"`
		Components struct {
			SecuritySchemes map[string]any `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.OpenAPI != "3.1.0" || len(doc.Paths) < 300 {
		t.Fatalf("openapi %q with %d paths", doc.OpenAPI, len(doc.Paths))
	}
	for _, k := range []string{"basicAuth", "bearerAuth", "cookieAuth", "mutualTLS"} {
		if doc.Components.SecuritySchemes[k] == nil {
			t.Fatalf("missing security scheme %s", k)
		}
	}
	get := func(path, method string) map[string]any {
		t.Helper()
		op := doc.Paths[path][method]
		if op == nil {
			t.Fatalf("missing %s %s", method, path)
		}
		return op
	}
	if op := get("/Marti/api/missions/{name}", "get"); op["x-access"] != "client" {
		t.Fatalf("mission get %v", op)
	}
	if op := get("/Marti/api/version", "get"); len(op["security"].([]any)) != 0 {
		t.Fatalf("public route requires security: %v", op)
	}
	op := get("/api/certs/{serial}/revoke", "post")
	if op["x-access"] != "admin" || op["summary"] != "Cert revoke" || op["operationId"] != "apiCertRevoke" {
		t.Fatalf("admin route %v", op)
	}
	params := op["parameters"].([]any)
	if len(params) != 1 || params[0].(map[string]any)["name"] != "serial" {
		t.Fatalf("params %v", params)
	}
	get("/takproto/1", "get")
	get("/Marti/api/device/profile/{name}/files", "get")
	for path := range doc.Paths {
		if strings.Contains(path, "...") || strings.Contains(path, "{$}") || strings.Contains(path, " ") {
			t.Fatalf("bad path %q", path)
		}
	}

	st, y := doReq(t, http.DefaultClient, "GET", plainURL(s, "/v3/api-docs.yaml"), nil, admin)
	if st != http.StatusOK || !strings.Contains(string(y), "\"openapi\": \"3.1.0\"") || !strings.Contains(string(y), "\"/Marti/api/missions/{name}\":") {
		t.Fatalf("yaml %d %.300s", st, y)
	}
	req, _ := http.NewRequest("GET", plainURL(s, "/swagger-ui/index.html"), nil)
	for k, v := range admin {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatalf("explorer %d %v", resp.StatusCode, resp.Header)
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", plainURL(s, "/assets/api.js"), nil, nil); st != http.StatusOK {
		t.Fatalf("explorer script %d", st)
	}
}

func TestDocumentedSubRoutesAreHandled(t *testing.T) {
	s := newTestServer(t, nil)
	for _, rd := range subRouteDocs() {
		if rd.Method == http.MethodHead {
			continue
		}
		path := pathParam.ReplaceAllString(rd.Path, "x1")
		st, b, _ := s.LocalRequest(rd.Method, path, nil)
		if strings.Contains(string(b), "not implemented: ") {
			t.Errorf("%s %s is documented but not handled (%d)", rd.Method, rd.Path, st)
		}
	}
}

func TestRouteTagAndHumanize(t *testing.T) {
	cases := map[string]string{"/Marti/api/missions/{name}": "Marti missions", "/Marti/sync/content": "Marti sync", "/api/users/{name}": "users", "/metrics": "metrics", "/": "dashboard", "/Marti/api/{x}": "Marti api"}
	for in, want := range cases {
		if got := routeTag(in); got != want {
			t.Errorf("routeTag(%q) = %q, want %q", in, got, want)
		}
	}
	if got := humanize("martiMissionGetByGUID"); got != "Mission get by guid" {
		t.Errorf("humanize %q", got)
	}
}
