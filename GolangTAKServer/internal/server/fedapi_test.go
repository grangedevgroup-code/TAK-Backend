package server

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
)

func TestFederationAPIGroupMapping(t *testing.T) {
	a, b := fed2Pair(t, nil)
	h := adminHeaders(t, b)
	var fedID string
	waitFor(t, "the federate to be listed", 5*time.Second, func() bool {
		_, body := doReq(t, http.DefaultClient, "GET", plainURL(b, "/Marti/api/federates"), nil, h)
		var env struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		json.Unmarshal(body, &env)
		if len(env.Data) > 0 {
			fedID = env.Data[0].ID
			return true
		}
		return false
	})
	port := freePort(t)
	if st, body := doReq(t, http.DefaultClient, "POST", plainURL(b, "/Marti/api/inputs"), strings.NewReader(`{"name":"ops","protocol":"stcp","port":`+itoa(port)+`,"auth":"anonymous","filtergroup":["Ops"]}`), h); st != 200 {
		t.Fatalf("input: %d %s", st, body)
	}
	if st, body := doReq(t, http.DefaultClient, "POST", plainURL(b, "/Marti/api/federategroupsmap/"+url.PathEscape(fedID)+"?remoteGroup=__ANON__&localGroup=Ops"), nil, h); st != 200 || !strings.Contains(string(body), `"Ops"`) {
		t.Fatalf("group map: %d %s", st, body)
	}
	ops := dialPort(t, port)
	anon := dialTCP(t, b)
	src := dialTCP(t, a)
	ops.send(saXML("OPS-1", "OPS1", 1, 1))
	anon.send(saXML("ANON-1", "ANON1", 1, 1))
	time.Sleep(200 * time.Millisecond)
	src.send(saXML("FED-A", "FEDA", 1, 1))
	ops.expect(func(e *cot.Event) bool { return e.UID == "FED-A" }, "mapped group receives federated traffic")
	anon.expectNone(func(e *cot.Event) bool { return e.UID == "FED-A" }, "unmapped group must not receive it", 700*time.Millisecond)
	if st, body := doReq(t, http.DefaultClient, "POST", plainURL(b, "/Marti/api/federategroups"), strings.NewReader(`{"federateId":"`+fedID+`","group":"Nobody","direction":"OUTBOUND"}`), h); st != 200 {
		t.Fatalf("outbound group: %d %s", st, body)
	}
	anon.send(saXML("ANON-2", "ANON2", 3, 3))
	src.expectNone(func(e *cot.Event) bool { return e.UID == "ANON-2" }, "traffic outside the outbound groups must not federate", 700*time.Millisecond)
	_, body := doReq(t, http.DefaultClient, "GET", plainURL(b, "/Marti/api/federatedetails/"+url.PathEscape(fedID)), nil, h)
	if !strings.Contains(string(body), `"outboundGroup":["Nobody"]`) || !strings.Contains(string(body), `"__ANON__:Ops"`) {
		t.Fatalf("details: %s", body)
	}
	_, body = doReq(t, http.DefaultClient, "GET", plainURL(b, "/Marti/api/federationconfig"), nil, h)
	if !strings.Contains(string(body), `"enabled":true`) {
		t.Fatalf("federation config: %s", body)
	}
}
