package aws

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSigningKeyAWSExample(t *testing.T) {
	k := SigningKey("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215", "us-east-1", "iam")
	if got := hex.EncodeToString(k); got != "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d" {
		t.Fatalf("signing key %s", got)
	}
}

func TestSignAWSListUsersExample(t *testing.T) {
	r, _ := http.NewRequest("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", nil)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	now := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	r.Header.Set("X-Amz-Date", "20150830T123600Z")
	cr := CanonicalRequest(r, sha256Hex(nil), []string{"content-type", "host", "x-amz-date"})
	if got := sha256Hex([]byte(cr)); got != "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59" {
		t.Fatalf("canonical request hash %s\n%s", got, cr)
	}
	Sign(r, nil, Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}, "us-east-1", "iam", now)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
	if got := r.Header.Get("Authorization"); got != want {
		t.Fatalf("authorization\n got %s\nwant %s", got, want)
	}
}

func TestSessionTokenIsSigned(t *testing.T) {
	r, _ := http.NewRequest("POST", "https://monitoring.eu-west-1.amazonaws.com/", strings.NewReader("Action=PutMetricData"))
	Sign(r, []byte("Action=PutMetricData"), Credentials{AccessKeyID: "AK", SecretAccessKey: "SK", SessionToken: "TOKEN"}, "eu-west-1", "monitoring", time.Now())
	if r.Header.Get("X-Amz-Security-Token") != "TOKEN" || !strings.Contains(r.Header.Get("Authorization"), "SignedHeaders=host;x-amz-date;x-amz-security-token") {
		t.Fatalf("headers %v", r.Header)
	}
}
