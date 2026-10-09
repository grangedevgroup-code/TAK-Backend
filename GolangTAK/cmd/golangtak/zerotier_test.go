package main

import (
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestZeroTierParsing(t *testing.T) {
	var nets []ztNetwork
	raw := `[{"nwid":"8056c2e21c000001","name":"field","status":"OK","assignedAddresses":["10.147.17.5/24","fd80:56c2:e21c::1/88"]},{"nwid":"8056c2e21c000002","status":"ACCESS_DENIED","assignedAddresses":[]}]`
	if err := json.Unmarshal([]byte(raw), &nets); err != nil {
		t.Fatal(err)
	}
	if got := ztIPs(nets[0]); !slices.Equal(got, []string{"10.147.17.5", "fd80:56c2:e21c::1"}) {
		t.Fatalf("addresses: %v", got)
	}
	if len(ztIPs(nets[1])) != 0 {
		t.Fatal("a denied network has no addresses")
	}
	for _, bad := range []string{"", "8056c2e21c00000", "8056c2e21c00000g", "../../etc/passwd"} {
		if _, err := zerotierJoin(t.TempDir(), bad, time.Second); err == nil {
			t.Errorf("%q accepted as a network ID", bad)
		}
	}
}
