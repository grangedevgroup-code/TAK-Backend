package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expires         time.Time
}

func (c Credentials) Valid() bool {
	return c.AccessKeyID != "" && c.SecretAccessKey != "" && (c.Expires.IsZero() || time.Now().Add(time.Minute).Before(c.Expires))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func SigningKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' || (path && c == '/') {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func CanonicalRequest(r *http.Request, payloadHash string, signed []string) string {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	var hdrs strings.Builder
	for _, h := range signed {
		v := r.Header.Get(h)
		if h == "host" {
			v = r.Host
			if v == "" {
				v = r.URL.Host
			}
		}
		hdrs.WriteString(h + ":" + strings.Join(strings.Fields(v), " ") + "\n")
	}
	return r.Method + "\n" + path + "\n" + canonicalQuery(r.URL.Query()) + "\n" + hdrs.String() + "\n" + strings.Join(signed, ";") + "\n" + payloadHash
}

func Sign(r *http.Request, body []byte, c Credentials, region, service string, now time.Time) {
	now = now.UTC()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	r.Header.Set("X-Amz-Date", amzDate)
	if c.SessionToken != "" {
		r.Header.Set("X-Amz-Security-Token", c.SessionToken)
	}
	payload := sha256Hex(body)
	signed := []string{"host", "x-amz-date"}
	if r.Header.Get("Content-Type") != "" {
		signed = append(signed, "content-type")
	}
	if c.SessionToken != "" {
		signed = append(signed, "x-amz-security-token")
	}
	sort.Strings(signed)
	scope := date + "/" + region + "/" + service + "/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(CanonicalRequest(r, payload, signed)))
	sig := hex.EncodeToString(hmacSHA256(SigningKey(c.SecretAccessKey, date, region, service), sts))
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}
