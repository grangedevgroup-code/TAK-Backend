package server

import (
	"crypto/fips140"
	"encoding/json"
	"net/http"
	"testing"
)

func TestStatusReportsFIPSMode(t *testing.T) {
	s := newTestServer(t, nil)
	st, b := doReq(t, http.DefaultClient, "GET", plainURL(s, "/api/status"), nil, adminHeaders(t, s))
	if st != http.StatusOK {
		t.Fatalf("status %d", st)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	if v, ok := out["fips"].(bool); !ok || v != fips140.Enabled() {
		t.Fatalf("fips field %v, want %v", out["fips"], fips140.Enabled())
	}
}
