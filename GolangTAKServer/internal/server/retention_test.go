package server

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestCronSchedule(t *testing.T) {
	at := func(s string) time.Time {
		v, _ := time.Parse("2006-01-02 15:04", s)
		return v
	}
	cases := []struct {
		expr string
		when string
		want bool
	}{
		{"0 0 * * * *", "2026-10-18 13:00", true},
		{"0 0 * * * *", "2026-10-18 13:01", false},
		{"*/15 * * * *", "2026-10-18 13:45", true},
		{"*/15 * * * *", "2026-10-18 13:46", false},
		{"30 2 * * MON-FRI", "2026-10-19 02:30", true},
		{"30 2 * * MON-FRI", "2026-10-18 02:30", false},
		{"0 0 1 JAN ?", "2027-01-01 00:00", true},
		{"-", "2026-10-18 13:00", false},
	}
	for _, c := range cases {
		if got := scheduleDue(c.expr, at(c.when)); got != c.want {
			t.Errorf("%q at %s = %v, want %v", c.expr, c.when, got, c.want)
		}
	}
	for _, bad := range []string{"* * *", "61 * * * *", "* 25 * * *", "a b c d e"} {
		if validSchedule(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRetentionAPIAndMissionArchive(t *testing.T) {
	s := newTestServer(t, nil)
	a := adminHeaders(t, s)
	do := func(method, path, body string) (int, string) {
		t.Helper()
		st, b := doReq(t, http.DefaultClient, method, plainURL(s, path), strings.NewReader(body), a)
		return st, string(b)
	}
	if st, b := do("PUT", "/Marti/api/retention/policy", `{"cot":240,"geochat":48,"missionpackages":null,"files":25}`); st != 200 || !strings.Contains(b, `"cot":240`) || !strings.Contains(b, `"files":48`) {
		t.Fatalf("policy: %d %s", st, b)
	}
	if r := s.Config().Retention; r.HistoryDays != 10 || r.GeoChatDays != 2 || r.FileDays != 2 {
		t.Fatalf("policy not saved: %+v", r)
	}
	if st, _ := do("PUT", "/Marti/api/retention/service/schedule", `"0 0 3 * * *"`); st != 200 || s.Config().Retention.Schedule != "0 0 3 * * *" {
		t.Fatalf("schedule: %d %q", st, s.Config().Retention.Schedule)
	}
	if st, _ := do("PUT", "/Marti/api/retention/service/schedule", `"nonsense"`); st != 400 {
		t.Fatalf("bad schedule accepted: %d", st)
	}
	do("PUT", "/Marti/api/missions/oldops?creatorUid=A", "")
	if st, b := do("PUT", "/Marti/api/retention/missionarchiveconfig", `{"cronExpression":"-","timeToArchiveAfterNoActivityDays":0.0000001,"removeFromArchiveAfterDays":30}`); st != 200 {
		t.Fatalf("archive config: %d %s", st, b)
	}
	time.Sleep(50 * time.Millisecond)
	s.runMissionArchive()
	if _, ok := s.missions.Get("oldops"); ok {
		t.Fatal("inactive mission was not archived")
	}
	st, b := do("GET", "/Marti/api/retention/missionarchive", "")
	if st != 200 || !strings.Contains(b, `oldops`) {
		t.Fatalf("archive list: %d %s", st, b)
	}
	list := s.archive.db.All()
	if len(list) != 1 {
		t.Fatalf("archive entries: %d", len(list))
	}
	if st, b := do("POST", "/Marti/api/retention/restoremission", itoa(int(list[0].ID))); st != 200 {
		t.Fatalf("restore: %d %s", st, b)
	}
	if _, ok := s.missions.Get("oldops"); !ok {
		t.Fatal("mission not restored")
	}
	if st, _ := do("PUT", "/Marti/api/retention/mission/oldops/expiry/1999999999", ""); st != 200 {
		t.Fatalf("mission expiry: %d", st)
	}
	if m, _ := s.missions.Get("oldops"); m.Expiration != 1999999999 {
		t.Fatalf("expiry not set: %d", m.Expiration)
	}
}
