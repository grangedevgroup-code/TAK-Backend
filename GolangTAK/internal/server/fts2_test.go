package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestFreeTAKAdminAPI(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("ftsadmin", "fts-password", true, nil)
	secret, _, err := s.dir.CreateToken("ftsadmin", "api", "test", time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	api := "http://127.0.0.1:" + strconv.Itoa(s.Config().Ports.API)
	hdr := map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + secret}
	call := func(method, path, body string) (int, []byte) {
		var rd *strings.Reader
		if body != "" {
			rd = strings.NewReader(body)
		} else {
			rd = strings.NewReader("")
		}
		return doReq(t, http.DefaultClient, method, api+path, rd, hdr)
	}

	st, body := call("POST", "/ManageSystemUser/postSystemUser", `{"systemUsers":[{"Name":"bravo","Group":"Blue, Red","Password":"Bravo-Pass-2026","Certs":"true"},{"Name":"charlie","Group":"Blue"}]}`)
	if st != http.StatusCreated {
		t.Fatalf("post users: %d %s", st, body)
	}
	var created struct {
		SystemUsers []map[string]string `json:"systemUsers"`
	}
	json.Unmarshal(body, &created)
	if len(created.SystemUsers) != 2 || !strings.Contains(created.SystemUsers[0]["CertificatePackage"], "/dl/") || created.SystemUsers[1]["Password"] == "" {
		t.Fatalf("created: %s", body)
	}
	if u, ok := s.dir.User("bravo"); !ok || len(u.In) != 2 {
		t.Fatalf("bravo groups: %+v", u)
	}
	if st, body := call("PUT", "/ManageSystemUser/putSystemUser", `{"systemUsers":[{"uid":"bravo","group":"Green","password":"New-Bravo-2026"}]}`); st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}
	if u, _ := s.dir.User("bravo"); len(u.In) != 1 || u.In[0] != "Green" {
		t.Fatalf("bravo after put: %v", u.In)
	}
	if _, err := s.dir.CheckPassword("127.0.0.1", "bravo", "New-Bravo-2026"); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if st, _ := call("DELETE", "/ManageSystemUser/deleteSystemUser", `{"systemUsers":[{"uid":"ftsadmin"}]}`); st != http.StatusBadRequest {
		t.Fatal("deleting yourself was allowed")
	}
	if st, body := call("DELETE", "/ManageSystemUser/deleteSystemUser", `{"systemUsers":[{"uid":"charlie"}]}`); st != 200 {
		t.Fatalf("delete: %d %s", st, body)
	}
	if _, ok := s.dir.User("charlie"); ok {
		t.Fatal("charlie still exists")
	}

	if st, body := call("POST", "/FederationTable", `{"outgoingFederations":[{"name":"hq","address":"10.1.2.3","port":9000,"status":"Disabled"}]}`); st != 200 {
		t.Fatalf("fed post: %d %s", st, body)
	}
	_, body = call("GET", "/FederationTable", "")
	if !strings.Contains(string(body), `"address":"10.1.2.3"`) || !strings.Contains(string(body), `"status":"Disabled"`) {
		t.Fatalf("fed get: %s", body)
	}
	if p := s.Config().Peers; len(p) != 1 || p[0].URL != "fed://10.1.2.3:9000" || p[0].Enabled {
		t.Fatalf("peer: %+v", p)
	}
	call("DELETE", "/FederationTable", `{"federations":[{"id":"hq"}]}`)
	if len(s.Config().Peers) != 0 {
		t.Fatal("federation not deleted")
	}

	tmpl := `<checklist><checklistDetails><name>Comms check</name><description>Radio checks</description></checklistDetails><checklistColumns/><checklistTasks><checklistTask><value>Radio 1</value></checklistTask></checklistTasks></checklist>`
	st, body = doReq(t, http.DefaultClient, "POST", api+"/ExCheckTable?clientUid=ANDROID-1", strings.NewReader(tmpl), map[string]string{"Content-Type": "application/xml", "Authorization": "Bearer " + secret})
	if st != 200 {
		t.Fatalf("excheck post: %d %s", st, body)
	}
	uid := string(body)
	_, body = call("GET", "/ExCheckTable", "")
	if !strings.Contains(string(body), uid) || !strings.Contains(string(body), "Comms check") {
		t.Fatalf("excheck get: %s", body)
	}
	call("DELETE", "/ExCheckTable", `{"ExCheck":{"Templates":[{"uid":"`+uid+`"}],"Checklists":[]}}`)
	if _, body = call("GET", "/ExCheckTable", ""); strings.Contains(string(body), uid) {
		t.Fatalf("template not deleted: %s", body)
	}

	st, body = call("POST", "/ManageKML/postKML", `{"name":"Water point","latitude":38.91,"longitude":-77.02,"body":{"Capacity":"500 L","Status":"open"}}`)
	if st != 200 {
		t.Fatalf("kml: %d %s", st, body)
	}
	kmlUID := string(body)
	waitFor(t, "KML marker", 3*time.Second, func() bool {
		for _, m := range s.hub.Cached() {
			if m.Event.UID == kmlUID {
				return strings.Contains(m.Event.Remarks(), "Capacity: 500 L")
			}
		}
		return false
	})
	call("POST", "/ManageGeoObject/postGeoObject", `{"latitude":38.95,"longitude":-77.05,"attitude":"hostile","geoObject":"Ground","name":"Inside"}`)
	call("POST", "/ManageGeoObject/postGeoObject", `{"latitude":40.5,"longitude":-75.0,"attitude":"hostile","geoObject":"Ground","name":"Outside"}`)
	waitFor(t, "objects cached", 3*time.Second, func() bool {
		_, b := call("GET", "/ManageGeoObject/getGeoObjectByZone?north=39&south=38.9&east=-77&west=-77.1", "")
		return strings.Contains(string(b), "Inside")
	})
	_, body = call("GET", "/ManageGeoObject/getGeoObjectByZone?zone="+strings.ReplaceAll("-77.1 38.9,-77.0 38.9,-77.0 39.0,-77.1 39.0", " ", "%20"), "")
	if !strings.Contains(string(body), "Inside") || strings.Contains(string(body), "Outside") {
		t.Fatalf("zone polygon: %s", body)
	}
	if st, _ := call("GET", "/ManageGeoObject/getGeoObjectByZone?north=1", ""); st != http.StatusBadRequest {
		t.Fatal("incomplete zone accepted")
	}
}
