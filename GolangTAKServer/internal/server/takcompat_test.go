package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func cloudTAKParse(t *testing.T, jwt string) map[string]any {
	t.Helper()
	raw := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(jwt, ".", ""), "-", "+"), "_", "/")
	for len(raw)%4 != 0 {
		raw = raw[:len(raw)-1]
	}
	dec, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode the whole token at once: %v", err)
	}
	parts := strings.Split(string(dec), "}")
	if len(parts) < 2 {
		t.Fatal("unexpected token format")
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(parts[1]+"}"), &claims); err != nil {
		t.Fatalf("payload %q: %v", parts[1], err)
	}
	return claims
}

func TestOAuthLikeCloudTAK(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("cloudy", "cloudy-password", false, []string{"Blue"})
	c := httpsClient(s, nil)
	webtak := "https://127.0.0.1:" + strconv.Itoa(s.Config().Ports.Enroll)
	form := url.Values{"grant_type": {"password"}, "username": {"cloudy"}, "password": {"wrong"}}
	st, body := doReq(t, c, "POST", webtak+"/oauth/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if st != http.StatusBadRequest || !strings.Contains(string(body), "invalid_grant") {
		t.Fatalf("bad password: %d %s", st, body)
	}
	form.Set("password", "cloudy-password")
	st, body = doReq(t, c, "POST", webtak+"/oauth/token", strings.NewReader(form.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if st != 200 || json.Unmarshal(body, &tok) != nil || tok.AccessToken == "" {
		t.Fatalf("token: %d %s", st, body)
	}
	claims := cloudTAKParse(t, tok.AccessToken)
	if claims["sub"] != "cloudy" || claims["exp"].(float64) < float64(time.Now().Unix()) {
		t.Fatalf("claims %v", claims)
	}
	bearer := map[string]string{"Authorization": "Bearer " + tok.AccessToken}
	st, _ = doReq(t, c, "GET", webtak+"/Marti/api/tls/config", nil, bearer)
	if st != 200 {
		t.Fatalf("tls config: %d", st)
	}
	_, csr := newCSR(t, "cloudy")
	h := map[string]string{"Authorization": "Bearer " + tok.AccessToken, "Accept": "application/json"}
	st, body = doReq(t, c, "POST", webtak+"/Marti/api/tls/signClient/v2?clientUid=CloudTAK-cloudy&version=3", strings.NewReader(csr), h)
	if st != 200 || !strings.Contains(string(body), "signedCert") {
		t.Fatalf("certificate with the oauth token: %d %s", st, body)
	}
	if st, _ := doReq(t, c, "GET", webtak+"/Marti/api/groups/all", nil, map[string]string{"Authorization": "Bearer " + tok.AccessToken + "x"}); st == 200 {
		t.Fatal("tampered token accepted")
	}
	expired, _ := s.signOAuthToken("cloudy", -time.Minute)
	if _, err := s.parseOAuthToken(expired); err == nil {
		t.Fatal("expired token accepted")
	}
	if s.isMissionToken(tok.AccessToken) {
		t.Fatal("oauth token treated as a mission token")
	}
}

func TestTAKUserManagementAPI(t *testing.T) {
	s := newTestServer(t, nil)
	s.dir.AddUser("boss", "boss-password", true, nil)
	s.dir.AddUser("plain", "plain-password", false, nil)
	admin, _, _ := s.dir.CreateToken("boss", "api", "t", time.Hour, 0)
	user, _, _ := s.dir.CreateToken("plain", "api", "t", time.Hour, 0)
	a := map[string]string{"Authorization": "Bearer " + admin, "Content-Type": "application/json"}
	base := plainURL(s, "/Marti/api/user-management/api/")
	if st, _ := doReq(t, http.DefaultClient, "GET", base+"list-users", nil, map[string]string{"Authorization": "Bearer " + user}); st != http.StatusForbidden {
		t.Fatalf("non-admin listed users: %d", st)
	}
	if st, body := doReq(t, http.DefaultClient, "POST", base+"new-user", strings.NewReader(`{"username":"medic1","password":"Medic-Pass-1","groupList":["Blue"],"groupListIN":["Red"],"groupListOUT":["Green"]}`), a); st != 200 {
		t.Fatalf("new-user: %d %s", st, body)
	}
	st, body := doReq(t, http.DefaultClient, "GET", base+"get-groups-for-user/medic1", nil, a)
	var m takUserModel
	if st != 200 || json.Unmarshal(body, &m) != nil || strings.Join(m.GroupList, ",") != "Blue" || strings.Join(m.GroupListIN, ",") != "Red" || strings.Join(m.GroupListOUT, ",") != "Green" {
		t.Fatalf("groups: %d %s", st, body)
	}
	if _, err := s.dir.CheckPassword("1.2.3.4", "medic1", "Medic-Pass-1"); err != nil {
		t.Fatal("created user cannot sign in")
	}
	st, body = doReq(t, http.DefaultClient, "POST", base+"new-users", strings.NewReader(`{"usernameExpression":"team-[N]","startN":1,"endN":3,"groupList":["Blue"]}`), a)
	if st != 200 || strings.Count(string(body), "team-") != 3 {
		t.Fatalf("bulk: %d %s", st, body)
	}
	doReq(t, http.DefaultClient, "PUT", base+"update-group-users", strings.NewReader(`{"groupname":"Ops","usersInGroup":["team-1"],"usersInGroupIN":["team-2"]}`), a)
	_, body = doReq(t, http.DefaultClient, "GET", base+"users-in-group/Ops", nil, a)
	if !strings.Contains(string(body), `"usersInGroup":["team-1"]`) || !strings.Contains(string(body), `"usersInGroupIN":["team-2"]`) {
		t.Fatalf("users in group: %s", body)
	}
	if st, _ := doReq(t, http.DefaultClient, "PUT", base+"change-user-password", strings.NewReader(`{"username":"medic1","password":"New-Medic-Pass-2"}`), a); st != 200 {
		t.Fatal("password change failed")
	}
	if _, err := s.dir.CheckPassword("1.2.3.5", "medic1", "New-Medic-Pass-2"); err != nil {
		t.Fatal("new password not active")
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", base+"delete-user/medic1", nil, a); st != 200 {
		t.Fatal("delete failed")
	}
	if _, ok := s.dir.User("medic1"); ok {
		t.Fatal("user still exists")
	}
	_, body = doReq(t, http.DefaultClient, "GET", base+"list-groupnames", nil, a)
	if !strings.Contains(string(body), `"groupname":"Ops"`) {
		t.Fatalf("group names: %s", body)
	}
}

func TestPagedMissionsAndProperties(t *testing.T) {
	s := newTestServer(t, nil)
	for _, n := range []string{"alpha", "bravo", "charlie"} {
		doReq(t, http.DefaultClient, "PUT", plainURL(s, "/Marti/api/missions/"+n+"?creatorUid=ANDROID-x&tool=public"), nil, nil)
	}
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/pagedmissions?page=1&pagesize=2&tool=public"), nil, nil)
	if st != 200 || !strings.Contains(string(body), `"name":"charlie"`) || strings.Contains(string(body), `"name":"alpha"`) || !strings.Contains(string(body), `"total":3`) {
		t.Fatalf("paged: %d %s", st, body)
	}
	m, _ := s.missions.Get("bravo")
	props := plainURL(s, "/Marti/api/missions/guid/"+m.GUID+"/properties")
	if st, body := doReq(t, http.DefaultClient, "PUT", props+"?creatorUid=ANDROID-x", strings.NewReader(`{"key":"incident.type","value":"wildfire"}`), map[string]string{"Content-Type": "application/json"}); st != 200 {
		t.Fatalf("set property: %d %s", st, body)
	}
	_, body = doReq(t, http.DefaultClient, "GET", props+"?prefix=incident", nil, nil)
	if !strings.Contains(string(body), `"value":"wildfire"`) {
		t.Fatalf("list properties: %s", body)
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", props+"/incident.type?creatorUid=ANDROID-x", nil, nil); st != 200 {
		t.Fatal("delete property")
	}
	if st, _ := doReq(t, http.DefaultClient, "GET", props+"/incident.type", nil, nil); st != http.StatusNotFound {
		t.Fatal("deleted property still there")
	}
	if st, _ := doReq(t, http.DefaultClient, "DELETE", plainURL(s, "/Marti/api/missions?guid="+m.GUID+"&creatorUid=ANDROID-x"), nil, nil); st != 200 {
		t.Fatalf("delete by guid: %d", st)
	}
	if _, ok := s.missions.Get("bravo"); ok {
		t.Fatal("mission not deleted")
	}
}

func TestRepeaterAPI(t *testing.T) {
	s := newTestServer(t, nil)
	c := dialTCP(t, s)
	c.send(saXML("ANDROID-sos", "SOS", 1, 1))
	e := `<event version="2.0" uid="ANDROID-sos-9-1-1" type="b-a-o-tbl" how="m-g" time="` + time.Now().UTC().Format(time.RFC3339) + `" start="` + time.Now().UTC().Format(time.RFC3339) + `" stale="` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"><point lat="1" lon="1" hae="0" ce="1" le="1"/><detail><link uid="ANDROID-sos" type="a-f-G-U-C" relation="p-p"/><contact callsign="SOS-Alert"/><emergency type="911 Alert">SOS</emergency></detail></event>`
	c.send(e)
	waitFor(t, "the emergency", 5*time.Second, func() bool { return len(s.hub.Emergencies()) == 1 })
	st, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/repeater/list"), nil, nil)
	if st != 200 || !strings.Contains(string(body), `"repeatType":"Emergency"`) || !strings.Contains(string(body), "ANDROID-sos-9-1-1") {
		t.Fatalf("list: %d %s", st, body)
	}
	_, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/repeater/period"), nil, nil)
	if !strings.Contains(string(body), `"data":5000`) {
		t.Fatalf("period: %s", body)
	}
	_, body = doReq(t, http.DefaultClient, "GET", plainURL(s, "/Marti/api/repeater/remove/ANDROID-sos-9-1-1"), nil, nil)
	if !strings.Contains(string(body), `"data":true`) || len(s.hub.Emergencies()) != 0 {
		t.Fatalf("remove: %s", body)
	}
}
