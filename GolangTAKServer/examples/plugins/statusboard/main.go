package main

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/pkg/plugin"
)

type device struct {
	UID      string    `json:"uid"`
	Callsign string    `json:"callsign"`
	Team     string    `json:"team"`
	Lat      float64   `json:"lat"`
	Lon      float64   `json:"lon"`
	Last     time.Time `json:"last"`
	Stale    bool      `json:"stale"`
}

var page = template.Must(template.New("p").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title>
<style>
:root{color-scheme:light dark;--bg:#f4f4f3;--panel:#fff;--text:#1d1d20;--muted:#5d5d63;--line:rgba(20,20,22,.14);--ok:#1d8656;--bad:#cf3434}
@media (prefers-color-scheme:dark){:root{--bg:#1c1c1f;--panel:#232326;--text:#f2f2f2;--muted:#a3a3a8;--line:rgba(255,255,255,.12)}}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
h1{font-size:22px;margin:0 0 4px}p{color:var(--muted);margin:0 0 18px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line)}
th{font-size:12px;color:var(--muted);font-weight:600}.ok{color:var(--ok)}.stale{color:var(--bad)}
form{display:flex;gap:8px;margin:18px 0}input{flex:1;padding:9px;border:1px solid var(--line);background:var(--panel);color:inherit;font:inherit}
button{padding:9px 16px;border:0;background:var(--text);color:var(--bg);font:inherit;font-weight:600;cursor:pointer}
</style></head><body>
<h1>{{.Title}}</h1><p>Signed in as {{.User}}. Updates every 5 seconds.</p>
{{if .Broadcast}}<form id="f"><input id="m" placeholder="Message everyone" maxlength="500" required><button>Send</button></form>{{end}}
<table><thead><tr><th>Callsign</th><th>Team</th><th>Position</th><th>Last report</th><th>State</th></tr></thead><tbody id="rows"></tbody></table>
<script>
function load(){fetch("devices").then(r=>r.json()).then(list=>{var b=document.getElementById("rows");b.textContent="";list.forEach(d=>{var tr=document.createElement("tr");[d.callsign,d.team||"-",d.lat.toFixed(5)+", "+d.lon.toFixed(5),new Date(d.last).toLocaleTimeString(),d.stale?"stale":"reporting"].forEach((v,i)=>{var td=document.createElement("td");td.textContent=v;if(i==4)td.className=d.stale?"stale":"ok";tr.appendChild(td)});b.appendChild(tr)})})}
load();setInterval(load,5000);
var f=document.getElementById("f");if(f)f.addEventListener("submit",function(e){e.preventDefault();var m=document.getElementById("m");fetch("broadcast",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({message:m.value})}).then(r=>{if(r.ok)m.value=""})});
</script></body></html>`))

func main() {
	p, err := plugin.Load()
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	staleAfter := time.Duration(p.SettingInt("staleMinutes", 5)) * time.Minute

	var mu sync.Mutex
	devices := map[string]*device{}
	go p.Events(ctx, false, func(e plugin.Event) {
		if !e.IsDevice() || e.Callsign == "" {
			return
		}
		mu.Lock()
		devices[e.UID] = &device{UID: e.UID, Callsign: e.Callsign, Team: e.Team, Lat: e.Lat, Lon: e.Lon, Last: time.Now()}
		mu.Unlock()
	})

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		u, _ := plugin.UserOf(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		page.Execute(w, map[string]any{"Title": p.Setting("title", "Status board"), "User": u.Name, "Broadcast": p.SettingBool("allowBroadcast", true)})
	})
	mux.HandleFunc("GET /devices", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		list := make([]device, 0, len(devices))
		for _, d := range devices {
			c := *d
			c.Stale = time.Since(c.Last) > staleAfter
			list = append(list, c)
		}
		mu.Unlock()
		sort.Slice(list, func(i, j int) bool { return strings.ToLower(list[i].Callsign) < strings.ToLower(list[j].Callsign) })
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})
	mux.HandleFunc("POST /broadcast", func(w http.ResponseWriter, r *http.Request) {
		u, ok := plugin.UserOf(r)
		if !ok || !p.SettingBool("allowBroadcast", true) {
			http.Error(w, "not allowed", http.StatusForbidden)
			return
		}
		var body struct {
			Message string `json:"message"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body) != nil || strings.TrimSpace(body.Message) == "" {
			http.Error(w, "message required", http.StatusBadRequest)
			return
		}
		if err := p.Chat(r.Context(), "", u.Name+": "+body.Message); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	p.Log.Printf("status board at %s", p.PagePath(""))
	if err := p.Serve(ctx, mux); err != nil {
		log.Fatal(err)
	}
}
