package aws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func clearAWSEnv(t *testing.T) {
	for _, k := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_DEFAULT_PROFILE",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(k, "")
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestStaticAndEnvironmentCredentials(t *testing.T) {
	clearAWSEnv(t)
	if c, err := NewProvider(Credentials{AccessKeyID: "S", SecretAccessKey: "T"}).Get(context.Background()); err != nil || c.AccessKeyID != "S" {
		t.Fatalf("static %+v %v", c, err)
	}
	if _, err := NewProvider(Credentials{}).Get(context.Background()); err == nil {
		t.Fatal("credentials found with nothing configured")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENVSECRET")
	t.Setenv("AWS_SESSION_TOKEN", "ENVTOKEN")
	c, err := NewProvider(Credentials{}).Get(context.Background())
	if err != nil || c.AccessKeyID != "ENVKEY" || c.SessionToken != "ENVTOKEN" {
		t.Fatalf("env %+v %v", c, err)
	}
}

func TestSharedCredentialsFileProfiles(t *testing.T) {
	clearAWSEnv(t)
	f := filepath.Join(t.TempDir(), "credentials")
	os.WriteFile(f, []byte("[default]\naws_access_key_id = DEF\naws_secret_access_key = DEFSECRET\n\n# comment\n[profile tak]\naws_access_key_id=TAKKEY\naws_secret_access_key=TAKSECRET\naws_session_token = TAKTOKEN\n"), 0o600)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", f)
	if c, err := NewProvider(Credentials{}).Get(context.Background()); err != nil || c.AccessKeyID != "DEF" {
		t.Fatalf("default profile %+v %v", c, err)
	}
	t.Setenv("AWS_PROFILE", "tak")
	if c, err := NewProvider(Credentials{}).Get(context.Background()); err != nil || c.AccessKeyID != "TAKKEY" || c.SessionToken != "TAKTOKEN" {
		t.Fatalf("named profile %+v %v", c, err)
	}
	if _, err := ParseSharedCredentials(strings.NewReader("[other]\naws_access_key_id=x\n"), "default"); err == nil {
		t.Fatal("missing profile accepted")
	}
}

func TestContainerCredentials(t *testing.T) {
	clearAWSEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/credentials/abc" || r.Header.Get("Authorization") != "" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"AccessKeyId":"ECSKEY","SecretAccessKey":"ECSSECRET","Token":"ECSTOKEN","Expiration":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
	}))
	defer srv.Close()
	old := ECSEndpoint
	ECSEndpoint = srv.URL
	defer func() { ECSEndpoint = old }()
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/credentials/abc")
	c, err := NewProvider(Credentials{}).Get(context.Background())
	if err != nil || c.AccessKeyID != "ECSKEY" || c.SessionToken != "ECSTOKEN" || c.Expires.IsZero() {
		t.Fatalf("ecs %+v %v", c, err)
	}
}

func TestInstanceRoleCredentialsAndRegion(t *testing.T) {
	clearAWSEnv(t)
	t.Setenv("AWS_EC2_METADATA_DISABLED", "")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/latest/api/token" && r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds") != "" {
			w.Write([]byte("IMDSTOKEN"))
			return
		}
		if r.Header.Get("X-aws-ec2-metadata-token") != "IMDSTOKEN" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/latest/meta-data/iam/security-credentials/":
			w.Write([]byte("tak-server-role\n"))
		case "/latest/meta-data/iam/security-credentials/tak-server-role":
			calls++
			w.Write([]byte(`{"Code":"Success","AccessKeyId":"ROLEKEY","SecretAccessKey":"ROLESECRET","Token":"ROLETOKEN","Expiration":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `"}`))
		case "/latest/meta-data/placement/region":
			w.Write([]byte("us-gov-west-1"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := IMDSEndpoint
	IMDSEndpoint = srv.URL
	defer func() { IMDSEndpoint = old }()
	p := NewProvider(Credentials{})
	c, err := p.Get(context.Background())
	if err != nil || c.AccessKeyID != "ROLEKEY" || c.SessionToken != "ROLETOKEN" {
		t.Fatalf("imds %+v %v", c, err)
	}
	p.Get(context.Background())
	if calls != 1 {
		t.Fatalf("role credentials fetched %d times, want cached", calls)
	}
	if r := p.Region(context.Background()); r != "us-gov-west-1" {
		t.Fatalf("region %q", r)
	}
	t.Setenv("AWS_REGION", "eu-central-1")
	if r := p.Region(context.Background()); r != "eu-central-1" {
		t.Fatalf("region from env %q", r)
	}
}
