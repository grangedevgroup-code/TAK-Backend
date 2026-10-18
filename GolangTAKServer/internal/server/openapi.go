package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/web"
)

type routeDoc struct {
	Method  string
	Path    string
	Access  access
	Handler string
}

func handlerName(h http.HandlerFunc) string {
	if h == nil {
		return ""
	}
	f := runtime.FuncForPC(reflect.ValueOf(h).Pointer())
	if f == nil {
		return ""
	}
	n := f.Name()
	n = strings.TrimSuffix(n, "-fm")
	if i := strings.LastIndex(n, "."); i >= 0 {
		n = n[i+1:]
	}
	if strings.HasPrefix(n, "func") {
		return ""
	}
	return n
}

func splitPattern(p string) (method, path string) {
	if i := strings.IndexByte(p, ' '); i > 0 {
		return p[:i], strings.TrimSpace(p[i+1:])
	}
	return "", p
}

var missionDocRoutes = []string{
	"GET /Marti/api/missions", "DELETE /Marti/api/missions", "GET /Marti/api/missions/invitations", "GET /Marti/api/missions/all/invitations",
	"GET /Marti/api/missions/all/logs", "GET /Marti/api/missions/all/subscriptions", "GET /Marti/api/missions/all/subscriptions/guid",
	"POST /Marti/api/missions/logs/entries", "PUT /Marti/api/missions/logs/entries", "GET /Marti/api/missions/logs/entries/{id}", "DELETE /Marti/api/missions/logs/entries/{id}",
	"GET /Marti/api/missions/{name}", "PUT /Marti/api/missions/{name}", "POST /Marti/api/missions/{name}", "DELETE /Marti/api/missions/{name}",
	"GET /Marti/api/missions/{name}/archive", "GET /Marti/api/missions/{name}/changes", "GET /Marti/api/missions/{name}/children", "GET /Marti/api/missions/{name}/contacts",
	"GET /Marti/api/missions/{name}/cot", "GET /Marti/api/missions/{name}/kml", "GET /Marti/api/missions/{name}/parent", "GET /Marti/api/missions/{name}/log",
	"GET /Marti/api/missions/{name}/invitations", "GET /Marti/api/missions/{name}/role", "PUT /Marti/api/missions/{name}/role", "GET /Marti/api/missions/{name}/token",
	"GET /Marti/api/missions/{name}/subscription", "PUT /Marti/api/missions/{name}/subscription", "POST /Marti/api/missions/{name}/subscription", "DELETE /Marti/api/missions/{name}/subscription",
	"GET /Marti/api/missions/{name}/subscriptions", "GET /Marti/api/missions/{name}/subscriptions/roles", "PUT /Marti/api/missions/{name}/copy",
	"PUT /Marti/api/missions/{name}/contents", "DELETE /Marti/api/missions/{name}/contents", "PUT /Marti/api/missions/{name}/contents/missionpackage",
	"PUT /Marti/api/missions/{name}/content/{hash}/keywords", "DELETE /Marti/api/missions/{name}/content/{hash}/keywords",
	"PUT /Marti/api/missions/{name}/keywords", "DELETE /Marti/api/missions/{name}/keywords", "DELETE /Marti/api/missions/{name}/keywords/{keyword}",
	"PUT /Marti/api/missions/{name}/uid/{uid}/keywords", "DELETE /Marti/api/missions/{name}/uid/{uid}/keywords",
	"PUT /Marti/api/missions/{name}/password", "DELETE /Marti/api/missions/{name}/password", "PUT /Marti/api/missions/{name}/expiration",
	"POST /Marti/api/missions/{name}/externaldata", "DELETE /Marti/api/missions/{name}/externaldata/{id}", "POST /Marti/api/missions/{name}/externaldata/{id}/change",
	"POST /Marti/api/missions/{name}/invite", "PUT /Marti/api/missions/{name}/invite/{type}/{invitee}", "DELETE /Marti/api/missions/{name}/invite/{type}/{invitee}",
	"POST /Marti/api/missions/{name}/send", "POST /Marti/api/missions/{name}/feed", "DELETE /Marti/api/missions/{name}/feed/{uid}",
	"GET /Marti/api/missions/{name}/layers", "PUT /Marti/api/missions/{name}/layers", "DELETE /Marti/api/missions/{name}/layers", "PUT /Marti/api/missions/{name}/layers/parent",
	"GET /Marti/api/missions/{name}/layers/{layerUid}", "PUT /Marti/api/missions/{name}/layers/{layerUid}/name",
	"POST /Marti/api/missions/{name}/maplayers", "PUT /Marti/api/missions/{name}/maplayers", "DELETE /Marti/api/missions/{name}/maplayers/{uid}",
	"PUT /Marti/api/missions/{name}/parent/{parentName}", "DELETE /Marti/api/missions/{name}/parent",
	"GET /Marti/api/missions/guid/{guid}", "GET /Marti/api/missions/guid/{guid}/children", "GET /Marti/api/missions/guid/{guid}/changes",
	"GET /Marti/api/missions/guid/{guid}/contacts", "GET /Marti/api/missions/guid/{guid}/cot", "GET /Marti/api/missions/guid/{guid}/kml",
	"GET /Marti/api/missions/guid/{guid}/invitations", "GET /Marti/api/missions/guid/{guid}/role", "PUT /Marti/api/missions/guid/{guid}/role",
	"GET /Marti/api/missions/guid/{guid}/subscription", "PUT /Marti/api/missions/guid/{guid}/subscription", "POST /Marti/api/missions/guid/{guid}/subscription", "DELETE /Marti/api/missions/guid/{guid}/subscription",
	"GET /Marti/api/missions/guid/{guid}/subscriptions", "GET /Marti/api/missions/guid/{guid}/subscriptions/roles",
	"GET /Marti/api/missions/guid/{guid}/properties", "PUT /Marti/api/missions/guid/{guid}/properties", "DELETE /Marti/api/missions/guid/{guid}/properties",
	"GET /Marti/api/missions/guid/{guid}/properties/{key}", "DELETE /Marti/api/missions/guid/{guid}/properties/{key}",
	"PUT /Marti/api/missions/guid/{guid}/contents", "DELETE /Marti/api/missions/guid/{guid}/contents", "PUT /Marti/api/missions/guid/{guid}/expiration",
	"PUT /Marti/api/missions/guid/{guid}/password", "DELETE /Marti/api/missions/guid/{guid}/password",
	"POST /Marti/api/missions/guid/{guid}/externaldata", "DELETE /Marti/api/missions/guid/{guid}/externaldata/{id}", "POST /Marti/api/missions/guid/{guid}/externaldata/{id}/change",
	"POST /Marti/api/missions/guid/{guid}/invite", "PUT /Marti/api/missions/guid/{guid}/invite/{type}/{invitee}", "DELETE /Marti/api/missions/guid/{guid}/invite/{type}/{invitee}",
	"POST /Marti/api/missions/guid/{guid}/send", "GET /Marti/api/missions/guid/{guid}/layers", "PUT /Marti/api/missions/guid/{guid}/layers", "DELETE /Marti/api/missions/guid/{guid}/layers",
	"PUT /Marti/api/missions/guid/{guid}/layers/parent", "GET /Marti/api/missions/guid/{guid}/layers/{layerUid}", "PUT /Marti/api/missions/guid/{guid}/layers/{layerUid}/name",
	"PUT /Marti/api/missions/guid/{guid}/layers/{layerUid}/position", "POST /Marti/api/missions/guid/{guid}/maplayers", "PUT /Marti/api/missions/guid/{guid}/maplayers",
	"PUT /Marti/api/missions/guid/{guid}/parent/guid/{parentGuid}", "DELETE /Marti/api/missions/guid/{guid}/parent",
}

var deviceProfileDocRoutes = []string{
	"GET /Marti/api/device/profile", "GET /Marti/api/device/profile/connection", "GET /Marti/api/device/profile/directories",
	"GET /Marti/api/device/profile/tool/{toolName}", "GET /Marti/api/device/profile/tool/{toolName}/file",
	"GET /Marti/api/device/profile/{name}", "PUT /Marti/api/device/profile/{name}", "POST /Marti/api/device/profile/{name}", "DELETE /Marti/api/device/profile/{name}",
	"GET /Marti/api/device/profile/{name}/files", "PUT /Marti/api/device/profile/{name}/file", "GET /Marti/api/device/profile/{name}/file/{id}", "DELETE /Marti/api/device/profile/{name}/file/{id}",
	"GET /Marti/api/device/profile/{name}/directories", "PUT /Marti/api/device/profile/{name}/directories/{directories}", "DELETE /Marti/api/device/profile/{name}/directories",
	"GET /Marti/api/device/profile/{name}/missionpackage", "HEAD /Marti/api/device/profile/{name}/missionpackage", "POST /Marti/api/device/profile/{name}/send",
}

func subRouteDocs() []routeDoc {
	var out []routeDoc
	for _, list := range [][]string{missionDocRoutes, deviceProfileDocRoutes} {
		for _, p := range list {
			m, path := splitPattern(p)
			out = append(out, routeDoc{Method: m, Path: path, Access: accessMarti})
		}
	}
	return out
}

var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

func openAPIPath(p string) (string, []string) {
	p = strings.ReplaceAll(p, "{$}", "")
	var names []string
	out := pathParam.ReplaceAllStringFunc(p, func(m string) string {
		n := strings.TrimSuffix(strings.Trim(m, "{}"), "...")
		names = append(names, n)
		return "{" + n + "}"
	})
	return out, names
}

func routeTag(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return "dashboard"
	}
	i := 0
	if strings.EqualFold(segs[0], "Marti") {
		i = 1
		if len(segs) > 1 && segs[1] == "api" {
			i = 2
		}
	} else if segs[0] == "api" {
		i = 1
	}
	if i >= len(segs) || strings.HasPrefix(segs[i], "{") {
		i = min(i, len(segs)-1)
		if i > 0 {
			i--
		}
	}
	tag := segs[i]
	if strings.EqualFold(segs[0], "Marti") && i == 1 {
		return "Marti " + tag
	}
	if strings.EqualFold(segs[0], "Marti") {
		return "Marti " + tag
	}
	return tag
}

func humanize(name string) string {
	var words []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	rs := []rune(name)
	for i, r := range rs {
		if unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || (i+1 < len(rs) && unicode.IsLower(rs[i+1]))) {
			flush()
		}
		cur = append(cur, r)
	}
	flush()
	if len(words) > 1 && (words[0] == "marti" || words[0] == "api" || words[0] == "tak") {
		words = words[1:]
	}
	if len(words) == 0 {
		return ""
	}
	s := strings.Join(words, " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

func (s *Server) recordRoute(docs *[]routeDoc, pattern string, level access, h http.HandlerFunc) {
	m, p := splitPattern(pattern)
	*docs = append(*docs, routeDoc{Method: m, Path: p, Access: level, Handler: handlerName(h)})
}

func (s *Server) openAPIDocument(r *http.Request) map[string]any {
	var routes []routeDoc
	if p := s.apiRoutes.Load(); p != nil {
		routes = *p
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	secured := []any{map[string]any{"basicAuth": []any{}}, map[string]any{"bearerAuth": []any{}}, map[string]any{"cookieAuth": []any{}}, map[string]any{"mutualTLS": []any{}}}
	paths := map[string]any{}
	ids := map[string]int{}
	tags := map[string]bool{}
	for _, rd := range routes {
		if strings.HasSuffix(rd.Path, "/") && rd.Path != "/" || strings.Contains(rd.Path, "{$}") || rd.Path == "/favicon.ico" {
			continue
		}
		path, params := openAPIPath(rd.Path)
		methods := []string{strings.ToLower(rd.Method)}
		if rd.Method == "" {
			methods = []string{"get", "post"}
		}
		item, _ := paths[path].(map[string]any)
		if item == nil {
			item = map[string]any{}
			paths[path] = item
		}
		for _, method := range methods {
			if _, dup := item[method]; dup {
				continue
			}
			tag := routeTag(rd.Path)
			tags[tag] = true
			summary := humanize(rd.Handler)
			if summary == "" {
				summary = strings.ToUpper(method) + " " + path
			}
			op := map[string]any{"tags": []any{tag}, "summary": summary, "responses": map[string]any{"200": map[string]any{"description": "Success"}}}
			if rd.Handler != "" {
				id := rd.Handler
				if n := ids[id]; n > 0 {
					id += strconv.Itoa(n + 1)
				}
				ids[rd.Handler]++
				op["operationId"] = id
			}
			var ps []any
			for _, n := range params {
				ps = append(ps, map[string]any{"name": n, "in": "path", "required": true, "schema": map[string]any{"type": "string"}})
			}
			if len(ps) > 0 {
				op["parameters"] = ps
			}
			switch rd.Access {
			case accessAny:
				op["security"] = []any{}
			default:
				op["security"] = secured
				resp := op["responses"].(map[string]any)
				resp["401"] = map[string]any{"description": "Not signed in"}
				if rd.Access == accessAdmin {
					resp["403"] = map[string]any{"description": "Requires an administrator"}
					op["x-access"] = "admin"
				} else if rd.Access == accessUser {
					op["x-access"] = "user"
				} else {
					op["x-access"] = "client"
				}
			}
			item[method] = op
		}
	}
	var tagList []any
	var names []string
	for t := range tags {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		tagList = append(tagList, map[string]any{"name": t})
	}
	return map[string]any{
		"openapi": "3.1.0",
		"info": map[string]any{"title": "GolangTAKServer API", "version": s.Version,
			"description": "REST API of GolangTAKServer, including the TAK Server compatible Marti API. Generated from the routes this server is running."},
		"servers": []any{map[string]any{"url": scheme + "://" + r.Host}},
		"tags":    tagList,
		"paths":   paths,
		"components": map[string]any{"securitySchemes": map[string]any{
			"basicAuth":  map[string]any{"type": "http", "scheme": "basic"},
			"bearerAuth": map[string]any{"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
			"cookieAuth": map[string]any{"type": "apiKey", "in": "cookie", "name": sessionCookie},
			"mutualTLS":  map[string]any{"type": "mutualTLS", "description": "Client certificate issued by this server's certificate authority"},
		}},
	}
}

func (s *Server) apiOpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.openAPIDocument(r))
}

func (s *Server) apiOpenAPIYAML(w http.ResponseWriter, r *http.Request) {
	b, _ := json.Marshal(s.openAPIDocument(r))
	var v any
	json.Unmarshal(b, &v)
	var buf bytes.Buffer
	writeYAML(&buf, v, 0, false)
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Write(buf.Bytes())
}

func yamlScalar(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		b, _ := json.Marshal(x)
		return string(b)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func writeYAML(buf *bytes.Buffer, v any, indent int, inList bool) {
	pad := strings.Repeat("  ", indent)
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			buf.WriteString("{}\n")
			return
		}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 || !inList {
				buf.WriteString(pad)
			}
			buf.WriteString(yamlScalar(k) + ":")
			writeYAMLValue(buf, x[k], indent+1)
		}
	case []any:
		if len(x) == 0 {
			buf.WriteString("[]\n")
			return
		}
		for _, e := range x {
			buf.WriteString(pad + "- ")
			switch e.(type) {
			case map[string]any:
				if len(e.(map[string]any)) == 0 {
					buf.WriteString("{}\n")
					continue
				}
				writeYAML(buf, e, indent+1, true)
			case []any:
				buf.WriteString("\n")
				writeYAML(buf, e, indent+1, false)
			default:
				buf.WriteString(yamlScalar(e) + "\n")
			}
		}
	default:
		buf.WriteString(pad + yamlScalar(v) + "\n")
	}
}

func writeYAMLValue(buf *bytes.Buffer, v any, indent int) {
	switch x := v.(type) {
	case map[string]any:
		if len(x) == 0 {
			buf.WriteString(" {}\n")
			return
		}
		buf.WriteString("\n")
		writeYAML(buf, x, indent, false)
	case []any:
		if len(x) == 0 {
			buf.WriteString(" []\n")
			return
		}
		buf.WriteString("\n")
		writeYAML(buf, x, indent, false)
	default:
		buf.WriteString(" " + yamlScalar(v) + "\n")
	}
}

func (s *Server) apiExplorer(w http.ResponseWriter, r *http.Request) {
	b, err := fsReadFile(web.Assets(), "api.html")
	if err != nil {
		writeText(w, http.StatusNotFound, "API explorer missing")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}
