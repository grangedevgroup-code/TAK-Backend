package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/pki"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/server"
)

type userInfo struct {
	Name      string    `json:"name"`
	Admin     bool      `json:"admin"`
	Disabled  bool      `json:"disabled"`
	In        []string  `json:"in"`
	Out       []string  `json:"out"`
	Callsign  string    `json:"callsign"`
	LastLogin time.Time `json:"lastLogin"`
	Online    int       `json:"online"`
	Certs     []struct {
		Serial  string    `json:"serial"`
		Expires time.Time `json:"expires"`
		Revoked bool      `json:"revoked"`
	} `json:"certs"`
}

func table() *tabwriter.Writer { return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0) }

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func when(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func groupsText(in, out []string) string {
	if strings.Join(in, ",") == strings.Join(out, ",") {
		return orDash(strings.Join(in, ","))
	}
	return "in:" + orDash(strings.Join(in, ",")) + " out:" + orDash(strings.Join(out, ","))
}

func need(a *args, n int) error {
	if len(a.pos) < n {
		return errUsage
	}
	return nil
}

func cmdUser(a *args) error {
	if err := need(a, 1); err != nil {
		return err
	}
	sub := strings.ToLower(a.arg(0))
	name := a.arg(1)
	return withClient(a, func(c *client) error {
		esc := url.PathEscape(name)
		switch sub {
		case "list", "ls":
			var users []userInfo
			if err := c.call("GET", "/api/users", nil, &users); err != nil {
				return err
			}
			sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
			t := table()
			fmt.Fprintln(t, "NAME\tROLE\tGROUPS\tCERTS\tONLINE\tLAST SIGN-IN")
			for _, u := range users {
				role := "user"
				if u.Admin {
					role = "admin"
				}
				if u.Disabled {
					role += " (disabled)"
				}
				certs := 0
				for _, ce := range u.Certs {
					if !ce.Revoked {
						certs++
					}
				}
				fmt.Fprintf(t, "%s\t%s\t%s\t%d\t%d\t%s\n", u.Name, role, groupsText(u.In, u.Out), certs, u.Online, when(u.LastLogin))
			}
			return t.Flush()
		case "add", "create", "new":
			if name == "" {
				return errUsage
			}
			body := map[string]any{"name": name, "password": a.val("password"), "admin": a.on("admin"), "groups": splitList(a.val("groups"))}
			if v := a.val("callsign"); v != "" {
				body["callsign"] = v
			}
			if v := a.val("team"); v != "" {
				body["team"] = v
			}
			if v := a.val("role"); v != "" {
				body["teamRole"] = v
			}
			var res struct {
				Password string `json:"password"`
			}
			if err := c.call("POST", "/api/users", body, &res); err != nil {
				return err
			}
			fmt.Printf("User %s created.\n", name)
			if res.Password != "" {
				fmt.Printf("Password: %s\n", res.Password)
			}
			fmt.Printf("Connect a device: golangtak qr %s   or   golangtak user package %s\n", name, name)
			return nil
		case "del", "delete", "rm", "remove":
			if name == "" {
				return errUsage
			}
			var res struct {
				Revoked int `json:"revoked"`
			}
			if err := c.call("DELETE", "/api/users/"+esc, nil, &res); err != nil {
				return err
			}
			fmt.Printf("User %s deleted (%d certificate(s) revoked).\n", name, res.Revoked)
			return nil
		case "passwd", "password":
			if name == "" {
				return errUsage
			}
			pw := firstNonEmpty(a.arg(2), a.val("password"))
			generated := pw == ""
			if generated {
				pw = server.FriendlySecret()
			}
			if err := c.call("PUT", "/api/users/"+esc, map[string]any{"password": pw}, nil); err != nil {
				return err
			}
			if generated {
				fmt.Printf("New password for %s: %s\n", name, pw)
			} else {
				fmt.Printf("Password for %s changed.\n", name)
			}
			return nil
		case "admin":
			if name == "" {
				return errUsage
			}
			on := true
			switch strings.ToLower(a.arg(2)) {
			case "", "on", "yes", "true":
			case "off", "no", "false":
				on = false
			default:
				return errUsage
			}
			if err := c.call("PUT", "/api/users/"+esc, map[string]any{"admin": on}, nil); err != nil {
				return err
			}
			fmt.Printf("%s administrator access: %v\n", name, on)
			return nil
		case "disable", "enable":
			if name == "" {
				return errUsage
			}
			if err := c.call("PUT", "/api/users/"+esc, map[string]any{"disabled": sub == "disable"}, nil); err != nil {
				return err
			}
			fmt.Printf("User %s %sd.\n", name, sub)
			return nil
		case "groups":
			if name == "" {
				return errUsage
			}
			body := map[string]any{}
			if a.has("groups") {
				body["in"], body["out"] = splitList(a.val("groups")), splitList(a.val("groups"))
			}
			if a.has("in") {
				body["in"] = splitList(a.val("in"))
			}
			if a.has("out") {
				body["out"] = splitList(a.val("out"))
			}
			if len(body) > 0 {
				if err := c.call("PUT", "/api/users/"+esc, body, nil); err != nil {
					return err
				}
			}
			var u userInfo
			if err := c.call("GET", "/api/users/"+esc, nil, &u); err != nil {
				return err
			}
			fmt.Printf("%s receives from: %s\n%s sends to:     %s\n", u.Name, orDash(strings.Join(u.In, ", ")), u.Name, orDash(strings.Join(u.Out, ", ")))
			return nil
		case "revoke":
			if name == "" {
				return errUsage
			}
			var res map[string]any
			if err := c.call("POST", "/api/users/"+esc+"/revoke", nil, &res); err != nil {
				return err
			}
			fmt.Printf("Certificates of %s revoked: %v\n", name, res["revoked"])
			return nil
		case "package", "pkg":
			if name == "" {
				return errUsage
			}
			q := url.Values{"user": {name}, "type": {firstNonEmpty(a.val("type"), "cert")}}
			if v := a.val("host"); v != "" {
				q.Set("host", v)
			}
			return download(c, "/api/package?"+q.Encode(), firstNonEmpty(a.val("out-file"), a.arg(2)))
		case "qr":
			if name == "" {
				return errUsage
			}
			return printEnrollQR(c, name, a.val("host"))
		case "show", "info":
			if name == "" {
				return errUsage
			}
			var u userInfo
			if err := c.call("GET", "/api/users/"+esc, nil, &u); err != nil {
				return err
			}
			row := func(k, v string) { fmt.Printf("  %-12s %s\n", k, v) }
			row("Name", u.Name)
			row("Admin", strconv.FormatBool(u.Admin))
			row("Disabled", strconv.FormatBool(u.Disabled))
			row("Callsign", orDash(u.Callsign))
			row("Receives", orDash(strings.Join(u.In, ", ")))
			row("Sends", orDash(strings.Join(u.Out, ", ")))
			row("Online", strconv.Itoa(u.Online))
			row("Last login", when(u.LastLogin))
			for _, ce := range u.Certs {
				state := "valid until " + ce.Expires.Format("2006-01-02")
				if ce.Revoked {
					state = "revoked"
				}
				row("Certificate", ce.Serial+"  "+state)
			}
			return nil
		}
		return errUsage
	})
}

func download(c *client, path, out string) error {
	st, body, h, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	if st >= 400 {
		return apiError(st, body)
	}
	if out == "" {
		if _, params, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil && params["filename"] != "" {
			out = filepath.Base(params["filename"])
		} else {
			out = "golangtak-download.zip"
		}
	}
	if fi, err := os.Stat(out); err == nil && fi.IsDir() {
		name := "golangtak-download.zip"
		if _, params, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil && params["filename"] != "" {
			name = filepath.Base(params["filename"])
		}
		out = filepath.Join(out, name)
	}
	if err := os.WriteFile(out, body, 0o600); err != nil {
		return err
	}
	abs, _ := filepath.Abs(out)
	fmt.Printf("Saved %s (%d bytes)\n", abs, len(body))
	return nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

type connectInfo struct {
	Name     string       `json:"name"`
	Host     string       `json:"host"`
	Hosts    []string     `json:"hosts"`
	Ports    server.Ports `json:"ports"`
	ITAK     string       `json:"itak"`
	ITAKTCP  string       `json:"itakTcp"`
	TLS      string       `json:"tlsConnect"`
	TCP      string       `json:"tcpConnect"`
	Enroll   string       `json:"enrollUrl"`
	CAFinger string       `json:"caFingerprint"`
	TrustPW  string       `json:"truststorePassword"`
	Anon     bool         `json:"allowAnonymous"`
}

func printEnrollQR(c *client, user, host string) error {
	var res struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires"`
		ATAK    string    `json:"atak"`
		ITAK    string    `json:"itak"`
	}
	if err := c.call("POST", "/api/connect/enroll", map[string]any{"user": user, "host": host, "hours": 24}, &res); err != nil {
		return err
	}
	fmt.Printf("\n  ATAK / WinTAK: scan with ATAK (Settings > Network > Servers > Add > Scan QR) to enroll %s:\n\n", user)
	printQR(os.Stdout, res.ATAK)
	fmt.Printf("\n  iTAK: scan, then sign in as %s with the one-time code %s\n\n", user, res.Token)
	printQR(os.Stdout, res.ITAK)
	fmt.Printf("\n  The code works until %s.\n", res.Expires.Local().Format("2006-01-02 15:04"))
	return nil
}

func cmdConnect(a *args) error {
	return withClient(a, func(c *client) error {
		q := ""
		if h := a.val("host"); h != "" {
			q = "?host=" + url.QueryEscape(h)
		}
		var ci connectInfo
		if err := c.call("GET", "/api/connect"+q, nil, &ci); err != nil {
			return err
		}
		row := func(k, v string) { fmt.Printf("  %-14s %s\n", k, v) }
		row("Server", ci.Name)
		row("Address", ci.Host)
		if len(ci.Hosts) > 1 {
			row("Other names", strings.Join(ci.Hosts, ", "))
		}
		if ci.Ports.TLS > 0 {
			row("SSL", ci.TLS+"   (ATAK, WinTAK, iTAK, TAK Aware with certificates)")
		}
		if ci.Ports.TCP > 0 && ci.Anon {
			row("TCP", ci.TCP+"   (unencrypted)")
		}
		if ci.Ports.Enroll > 0 {
			row("Enrollment", ci.Enroll+"   (sign in with a user name and password to get a certificate)")
		}
		if ci.Ports.WebSocket > 0 {
			row("WebSocket", fmt.Sprintf("ws://%s:%d/", server.HostForURL(ci.Host), ci.Ports.WebSocket))
		}
		row("CA", ci.CAFinger)
		row("Truststore pw", ci.TrustPW)
		if user := a.val("user"); user != "" {
			return printEnrollQR(c, user, a.val("host"))
		}
		fmt.Printf("\n  iTAK quick connect:\n\n")
		printQR(os.Stdout, ci.ITAK)
		fmt.Println("\n  For an ATAK enrollment QR code run: golangtak qr USER")
		return nil
	})
}

func cmdQR(a *args) error {
	if user := a.arg(0); user != "" {
		return withClient(a, func(c *client) error { return printEnrollQR(c, user, a.val("host")) })
	}
	return withClient(a, func(c *client) error {
		q := ""
		if h := a.val("host"); h != "" {
			q = "?host=" + url.QueryEscape(h)
		}
		var ci connectInfo
		if err := c.call("GET", "/api/connect"+q, nil, &ci); err != nil {
			return err
		}
		fmt.Printf("\n  iTAK quick connect for %s:\n\n", ci.Host)
		printQR(os.Stdout, ci.ITAK)
		fmt.Println("\n  For an ATAK enrollment QR code for a user run: golangtak qr USER")
		return nil
	})
}

func cmdGroup(a *args) error {
	if err := need(a, 1); err != nil {
		return err
	}
	sub, name := strings.ToLower(a.arg(0)), a.arg(1)
	return withClient(a, func(c *client) error {
		switch sub {
		case "list", "ls":
			var groups []struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Members     int    `json:"members"`
				System      bool   `json:"system"`
			}
			if err := c.call("GET", "/api/groups", nil, &groups); err != nil {
				return err
			}
			t := table()
			fmt.Fprintln(t, "NAME\tMEMBERS\tDESCRIPTION")
			for _, g := range groups {
				fmt.Fprintf(t, "%s\t%d\t%s\n", g.Name, g.Members, orDash(g.Description))
			}
			return t.Flush()
		case "add", "create", "new":
			if name == "" {
				return errUsage
			}
			if err := c.call("POST", "/api/groups", map[string]any{"name": name, "description": a.val("description")}, nil); err != nil {
				return err
			}
			fmt.Printf("Group %s created. Add users with: golangtak user groups USER --groups %s\n", name, name)
			return nil
		case "del", "delete", "rm", "remove":
			if name == "" {
				return errUsage
			}
			if err := c.call("DELETE", "/api/groups/"+url.PathEscape(name), nil, nil); err != nil {
				return err
			}
			fmt.Printf("Group %s deleted.\n", name)
			return nil
		}
		return errUsage
	})
}

func getSettings(c *client) (map[string]any, error) {
	var cfg map[string]any
	err := c.call("GET", "/api/settings", nil, &cfg)
	return cfg, err
}

func putSettings(c *client, patch map[string]any) error {
	var res struct {
		Restart bool `json:"restartRequired"`
	}
	if err := c.call("PUT", "/api/settings", patch, &res); err != nil {
		return err
	}
	if res.Restart {
		if c.online() {
			if err := c.call("POST", "/api/restart", nil, nil); err != nil {
				return fmt.Errorf("saved, but the restart failed: %w", err)
			}
			fmt.Println("Saved. The server is restarting to apply the change.")
		} else {
			fmt.Println("Saved. The change applies when the server starts.")
		}
		return nil
	}
	fmt.Println("Saved.")
	return nil
}

func cmdPeer(a *args) error {
	if err := need(a, 1); err != nil {
		return err
	}
	sub, name := strings.ToLower(a.arg(0)), a.arg(1)
	return withClient(a, func(c *client) error {
		cfg, err := getSettings(c)
		if err != nil {
			return err
		}
		peers, _ := cfg["peers"].([]any)
		find := func() int {
			for i, p := range peers {
				if m, ok := p.(map[string]any); ok && strings.EqualFold(fmt.Sprint(m["name"]), name) {
					return i
				}
			}
			return -1
		}
		switch sub {
		case "list", "ls":
			var status []struct {
				Name  string    `json:"name"`
				URL   string    `json:"url"`
				State string    `json:"state"`
				Error string    `json:"error"`
				Since time.Time `json:"since"`
			}
			c.call("GET", "/api/peers", nil, &status)
			t := table()
			fmt.Fprintln(t, "NAME\tURL\tENABLED\tSTATE")
			for _, p := range peers {
				m, _ := p.(map[string]any)
				state := "-"
				for _, s := range status {
					if s.Name == fmt.Sprint(m["name"]) {
						state = s.State
						if s.Error != "" {
							state += " (" + s.Error + ")"
						}
					}
				}
				fmt.Fprintf(t, "%v\t%v\t%v\t%s\n", m["name"], m["url"], m["enabled"], state)
			}
			return t.Flush()
		case "add", "create", "new":
			if name == "" || a.arg(2) == "" {
				return errUsage
			}
			if find() >= 0 {
				return fmt.Errorf("a peer named %s already exists", name)
			}
			p := map[string]any{"name": name, "url": a.arg(2), "enabled": true, "direction": firstNonEmpty(a.val("direction"), "both"), "groups": splitList(a.val("groups"))}
			for flag, key := range map[string]string{"user": "username", "password": "password", "cert-password": "certPassword", "protocol": "protocol"} {
				if v := a.val(flag); v != "" {
					p[key] = v
				}
			}
			for flag, key := range map[string]string{"cert": "certFile", "trust": "trustFile"} {
				if v := a.val(flag); v != "" {
					abs, err := filepath.Abs(v)
					if err != nil {
						return err
					}
					if _, err := os.Stat(abs); err != nil {
						return err
					}
					p[key] = abs
				}
			}
			if a.on("insecure") {
				p["insecure"] = true
			}
			if a.on("no-presence") {
				p["noPresence"] = true
			}
			peers = append(peers, p)
		case "del", "delete", "rm", "remove":
			i := find()
			if i < 0 {
				return fmt.Errorf("no peer named %q", name)
			}
			peers = append(peers[:i], peers[i+1:]...)
		case "enable", "disable":
			i := find()
			if i < 0 {
				return fmt.Errorf("no peer named %q", name)
			}
			peers[i].(map[string]any)["enabled"] = sub == "enable"
		default:
			return errUsage
		}
		if peers == nil {
			peers = []any{}
		}
		return putSettings(c, map[string]any{"peers": peers})
	})
}

func lookup(cfg any, key string) (any, bool) {
	cur := cfg
	for _, part := range strings.Split(key, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		found := false
		for k, v := range m {
			if strings.EqualFold(k, part) {
				cur, found = v, true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return cur, true
}

func coerce(current any, raw string) (any, error) {
	switch current.(type) {
	case string:
		return raw, nil
	case bool:
		return strconv.ParseBool(raw)
	case float64:
		if f, err := strconv.ParseFloat(raw, 64); err == nil {
			return f, nil
		}
		return nil, fmt.Errorf("%q is not a number", raw)
	case []any, nil:
		if strings.HasPrefix(strings.TrimSpace(raw), "[") {
			var v any
			if err := json.Unmarshal([]byte(raw), &v); err != nil {
				return nil, err
			}
			return v, nil
		}
		list := []any{}
		for _, s := range splitList(raw) {
			list = append(list, s)
		}
		return list, nil
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil, errors.New("this setting needs a JSON value")
	}
	return v, nil
}

func patchFor(cfg map[string]any, key, raw string) (map[string]any, error) {
	current, ok := lookup(cfg, key)
	if !ok {
		return nil, fmt.Errorf("unknown setting %q (see 'golangtak config show')", key)
	}
	v, err := coerce(current, raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	parts := strings.Split(key, ".")
	root := map[string]any{}
	node, src := root, cfg
	for i, part := range parts {
		name := part
		for k := range src {
			if strings.EqualFold(k, part) {
				name = k
			}
		}
		if i == len(parts)-1 {
			node[name] = v
			break
		}
		next := map[string]any{}
		node[name] = next
		node = next
		src, _ = src[name].(map[string]any)
	}
	return root, nil
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if sm, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				merge(dm, sm)
				continue
			}
		}
		dst[k] = v
	}
}

func cmdConfig(a *args) error {
	if err := need(a, 1); err != nil {
		return err
	}
	sub := strings.ToLower(a.arg(0))
	if sub == "path" {
		fmt.Println(server.ConfigPath(dataDir(a)))
		return nil
	}
	return withClient(a, func(c *client) error {
		cfg, err := getSettings(c)
		if err != nil {
			return err
		}
		switch sub {
		case "show", "list", "ls":
			b, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Println(string(b))
			return nil
		case "get":
			if a.arg(1) == "" {
				return errUsage
			}
			v, ok := lookup(cfg, a.arg(1))
			if !ok {
				return fmt.Errorf("unknown setting %q", a.arg(1))
			}
			if s, ok := v.(string); ok {
				fmt.Println(s)
				return nil
			}
			b, _ := json.MarshalIndent(v, "", "  ")
			fmt.Println(string(b))
			return nil
		case "set":
			if len(a.pos) < 3 || len(a.pos)%2 == 0 {
				return errUsage
			}
			patch := map[string]any{}
			for i := 1; i+1 < len(a.pos); i += 2 {
				p, err := patchFor(cfg, a.pos[i], a.pos[i+1])
				if err != nil {
					return err
				}
				merge(patch, p)
			}
			return putSettings(c, patch)
		}
		return errUsage
	})
}

func cmdCert(a *args) error {
	if err := need(a, 1); err != nil {
		return err
	}
	sub := strings.ToLower(a.arg(0))
	dir := dataDir(a)
	switch sub {
	case "info", "show":
		b, err := os.ReadFile(filepath.Join(dir, "certs", "ca.pem"))
		if err != nil {
			return err
		}
		certs, err := pki.ParseCertPEM(b)
		if err != nil || len(certs) == 0 {
			return errors.New("ca.pem is not a valid certificate")
		}
		ca := certs[0]
		row := func(k, v string) { fmt.Printf("  %-14s %s\n", k, v) }
		row("CA", ca.Subject.String())
		row("Fingerprint", pki.Fingerprint(ca))
		row("Valid until", ca.NotAfter.Format("2006-01-02"))
		row("CA file", filepath.Join(dir, "certs", "ca.pem"))
		if sb, err := os.ReadFile(filepath.Join(dir, "certs", "server.pem")); err == nil {
			if sc, err := pki.ParseCertPEM(sb); err == nil && len(sc) > 0 {
				names := append([]string{}, sc[0].DNSNames...)
				for _, ip := range sc[0].IPAddresses {
					names = append(names, ip.String())
				}
				row("Server cert", "valid until "+sc[0].NotAfter.Format("2006-01-02"))
				row("Server names", strings.Join(names, ", "))
			}
		}
		return nil
	case "renew":
		return withClient(a, func(c *client) error {
			if err := c.call("POST", "/api/certs/server/renew", nil, nil); err != nil {
				return err
			}
			fmt.Println("Server certificate renewed.")
			return nil
		})
	case "revoke":
		if a.arg(1) == "" {
			return errUsage
		}
		return withClient(a, func(c *client) error {
			if err := c.call("POST", "/api/certs/"+url.PathEscape(a.arg(1))+"/revoke", nil, nil); err != nil {
				return err
			}
			fmt.Println("Certificate revoked.")
			return nil
		})
	case "import-ca":
		if len(a.pos) < 3 {
			return errUsage
		}
		certPEM, err := os.ReadFile(a.arg(1))
		if err != nil {
			return err
		}
		keyPEM, err := os.ReadFile(a.arg(2))
		if err != nil {
			return err
		}
		c, err := openClient(dir)
		if err != nil {
			return err
		}
		online := c.online()
		if !online {
			c.close()
		}
		ca, err := server.ImportCA(dir, certPEM, keyPEM, a.arg(3))
		if err != nil {
			if online {
				c.close()
			}
			return err
		}
		fmt.Printf("Imported CA %s (%s).\n", ca.Subject.CommonName, pki.Fingerprint(ca))
		fmt.Println("Certificates issued by the previous CA are no longer trusted; devices need new connection packages.")
		if online {
			defer c.close()
			if err := c.call("POST", "/api/restart", nil, nil); err != nil {
				return fmt.Errorf("imported, but the restart failed: %w", err)
			}
			fmt.Println("The server is restarting with the new CA.")
		}
		return nil
	}
	return errUsage
}

func cmdBackup(a *args) error {
	return withClient(a, func(c *client) error {
		path := "/api/backup"
		if a.on("files") {
			path += "?files=1"
		}
		return download(c, path, a.arg(0))
	})
}

func cmdLogs(a *args) error {
	dir := dataDir(a)
	path := filepath.Join(dir, "logs", "golangtak.log")
	n := 100
	if v := a.val("n"); v != "" {
		var err error
		if n, err = strconv.Atoi(v); err != nil || n < 0 {
			return errUsage
		}
	}
	f, err := os.Open(path)
	if err != nil {
		if !isAdmin() && errors.Is(err, os.ErrPermission) {
			if eerr := elevate(invocation); eerr == nil {
				os.Exit(0)
			}
		}
		return err
	}
	f.Close()
	for _, l := range tailFile(path, n) {
		fmt.Println(l)
	}
	if !a.on("f") && !a.on("follow") {
		return nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	offset := st.Size()
	stop := stopSignals()
	for {
		select {
		case <-stop:
			return nil
		case <-time.After(500 * time.Millisecond):
		}
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Size() < offset {
			offset = 0
		}
		if st.Size() == offset {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		f.Seek(offset, io.SeekStart)
		n, _ := io.Copy(os.Stdout, f)
		offset += n
		f.Close()
	}
}
