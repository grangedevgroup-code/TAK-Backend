package aws

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	IMDSEndpoint = "http://169.254.169.254"
	ECSEndpoint  = "http://169.254.170.2"
)

type Provider struct {
	Static  Credentials
	Client  *http.Client
	mu      sync.Mutex
	current Credentials
}

func NewProvider(static Credentials) *Provider {
	return &Provider{Static: static, Client: &http.Client{Timeout: 5 * time.Second}}
}

func (p *Provider) Get(ctx context.Context) (Credentials, error) {
	if p.Static.AccessKeyID != "" && p.Static.SecretAccessKey != "" {
		return p.Static, nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current.Valid() {
		return p.current, nil
	}
	for _, src := range []func(context.Context) (Credentials, error){p.fromEnv, p.fromSharedFile, p.fromECS, p.fromIMDS} {
		if c, err := src(ctx); err == nil && c.AccessKeyID != "" {
			p.current = c
			return c, nil
		}
	}
	return Credentials{}, errors.New("no AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, a shared credentials file, or run with an instance or task role")
}

func (p *Provider) fromEnv(context.Context) (Credentials, error) {
	id := firstEnv("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY")
	secret := firstEnv("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY")
	if id == "" || secret == "" {
		return Credentials{}, errors.New("not in the environment")
	}
	return Credentials{AccessKeyID: id, SecretAccessKey: secret, SessionToken: os.Getenv("AWS_SESSION_TOKEN")}, nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func sharedFile() string {
	if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
		return f
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".aws", "credentials")
}

func ParseSharedCredentials(r io.Reader, profile string) (Credentials, error) {
	var c Credentials
	section := ""
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimPrefix(strings.Trim(line, "[]"), "profile "))
			continue
		}
		if section != profile {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "aws_access_key_id":
			c.AccessKeyID = strings.TrimSpace(v)
		case "aws_secret_access_key":
			c.SecretAccessKey = strings.TrimSpace(v)
		case "aws_session_token":
			c.SessionToken = strings.TrimSpace(v)
		}
	}
	if c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return Credentials{}, errors.New("profile not found")
	}
	return c, nil
}

func (p *Provider) fromSharedFile(context.Context) (Credentials, error) {
	f, err := os.Open(sharedFile())
	if err != nil {
		return Credentials{}, err
	}
	defer f.Close()
	profile := firstEnv("AWS_PROFILE", "AWS_DEFAULT_PROFILE")
	if profile == "" {
		profile = "default"
	}
	return ParseSharedCredentials(f, profile)
}

type roleCredentials struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
}

func (p *Provider) getJSON(ctx context.Context, url string, hdr map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(out)
}

func (p *Provider) fromECS(ctx context.Context) (Credentials, error) {
	url := ""
	hdr := map[string]string{}
	if rel := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		url = ECSEndpoint + rel
	} else if full := os.Getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); full != "" {
		url = full
		if tok := os.Getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN"); tok != "" {
			hdr["Authorization"] = tok
		}
	}
	if url == "" {
		return Credentials{}, errors.New("not in a container with a task role")
	}
	var rc roleCredentials
	if err := p.getJSON(ctx, url, hdr, &rc); err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessKeyID: rc.AccessKeyID, SecretAccessKey: rc.SecretAccessKey, SessionToken: rc.Token, Expires: rc.Expiration}, nil
}

func (p *Provider) imdsToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, IMDSEndpoint+"/latest/api/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := p.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return strings.TrimSpace(string(b)), err
}

func (p *Provider) imdsGet(ctx context.Context, token, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, IMDSEndpoint+path, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-aws-ec2-metadata-token", token)
	resp, err := p.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	return string(b), err
}

func (p *Provider) fromIMDS(ctx context.Context) (Credentials, error) {
	if strings.EqualFold(os.Getenv("AWS_EC2_METADATA_DISABLED"), "true") {
		return Credentials{}, errors.New("instance metadata is disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tok, err := p.imdsToken(ctx)
	if err != nil {
		return Credentials{}, err
	}
	roles, err := p.imdsGet(ctx, tok, "/latest/meta-data/iam/security-credentials/")
	if err != nil {
		return Credentials{}, err
	}
	role := strings.TrimSpace(strings.SplitN(roles, "\n", 2)[0])
	if role == "" {
		return Credentials{}, errors.New("the instance has no role")
	}
	body, err := p.imdsGet(ctx, tok, "/latest/meta-data/iam/security-credentials/"+role)
	if err != nil {
		return Credentials{}, err
	}
	var rc roleCredentials
	if err := json.Unmarshal([]byte(body), &rc); err != nil {
		return Credentials{}, err
	}
	return Credentials{AccessKeyID: rc.AccessKeyID, SecretAccessKey: rc.SecretAccessKey, SessionToken: rc.Token, Expires: rc.Expiration}, nil
}

func (p *Provider) Region(ctx context.Context) string {
	if r := firstEnv("AWS_REGION", "AWS_DEFAULT_REGION"); r != "" {
		return r
	}
	if strings.EqualFold(os.Getenv("AWS_EC2_METADATA_DISABLED"), "true") {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	tok, err := p.imdsToken(ctx)
	if err != nil {
		return ""
	}
	r, err := p.imdsGet(ctx, tok, "/latest/meta-data/placement/region")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(r)
}
