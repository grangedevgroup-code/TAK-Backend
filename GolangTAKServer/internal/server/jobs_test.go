package server

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestJobsAPI(t *testing.T) {
	s := newTestServer(t, nil)
	admin := feedAdmin(t, s)
	list := func() map[string]JobView {
		_, body := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/jobs"), nil, admin)
		var jobs []JobView
		json.Unmarshal(body, &jobs)
		out := map[string]JobView{}
		for _, j := range jobs {
			out[j.ID] = j
		}
		return out
	}
	jobs := list()
	for _, id := range []string{"cleanup", "certificate", "repeated", "sync", "adsb", "ais", "letsencrypt"} {
		if _, ok := jobs[id]; !ok {
			t.Fatalf("job %s missing: %v", id, jobs)
		}
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/jobs/cleanup/run"), nil, admin); st != 200 {
		t.Fatalf("run: %d", st)
	}
	waitFor(t, "cleanup to run", 5*time.Second, func() bool { return list()["cleanup"].Runs == 1 })
	doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/jobs/repeated/pause"), nil, admin)
	s.runJob("repeated")
	if j := list()["repeated"]; !j.Paused || j.Runs != 0 {
		t.Fatalf("paused job ran: %+v", j)
	}
	doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/jobs/repeated/resume"), nil, admin)
	s.runJob("repeated")
	if j := list()["repeated"]; j.Paused || j.Runs != 1 {
		t.Fatalf("resumed job: %+v", j)
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/jobs/nope/run"), nil, admin); st != http.StatusNotFound {
		t.Fatal("unknown job accepted")
	}
	if st, _ := doReq(t, http.DefaultClient, "POST", plainURL(s, "/api/jobs/cleanup/explode"), nil, admin); st != http.StatusBadRequest {
		t.Fatal("unknown action accepted")
	}
	if j := list()["letsencrypt"]; j.Runs != 0 {
		t.Fatalf("letsencrypt ran while off: %+v", j)
	}
}
