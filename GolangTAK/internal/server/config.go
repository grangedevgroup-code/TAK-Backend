package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const DefaultName = "GolangTAK"

type Ports struct {
	TCP          int `json:"tcp"`
	TCPAlt       int `json:"tcpAlt"`
	TLS          int `json:"tls"`
	UDP          int `json:"udp"`
	HTTP         int `json:"http"`
	HTTPS        int `json:"https"`
	Enroll       int `json:"enroll"`
	WebSocket    int `json:"websocket"`
	Federation   int `json:"federation"`
	FederationV2 int `json:"federationV2"`
	API          int `json:"api"`
}

type MeshConfig struct {
	Enabled   bool     `json:"enabled"`
	Send      bool     `json:"send"`
	Groups    []string `json:"groups"`
	Interface string   `json:"interface"`
	TTL       int      `json:"ttl"`
	Protobuf  bool     `json:"protobuf"`
}

type CertConfig struct {
	Organization string `json:"organization"`
	Unit         string `json:"unit"`
	Password     string `json:"password"`
	KeyBits      int    `json:"keyBits"`
	ClientDays   int    `json:"clientDays"`
	ServerDays   int    `json:"serverDays"`
}

type RetentionConfig struct {
	HistoryDays int `json:"historyDays"`
	ChatDays    int `json:"chatDays"`
	FileDays    int `json:"fileDays"`
	MissionDays int `json:"missionDays"`
}

type LimitsConfig struct {
	MaxClients      int `json:"maxClients"`
	MaxPerIP        int `json:"maxPerIP"`
	MaxMessageBytes int `json:"maxMessageBytes"`
	MaxUploadMB     int `json:"maxUploadMB"`
	QueueLength     int `json:"queueLength"`
	IdleTimeoutSec  int `json:"idleTimeoutSec"`
	ReplayLimit     int `json:"replayLimit"`
	CacheLimit      int `json:"cacheLimit"`
}

type RepeaterConfig struct {
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"intervalSec"`
}

type FederationConfig struct {
	Enabled  bool     `json:"enabled"`
	Groups   []string `json:"groups"`
	TrustPEM []string `json:"trustedCAs"`
	MaxHops  int      `json:"maxHops"`
}

type PeerConfig struct {
	Name       string   `json:"name"`
	URL        string   `json:"url"`
	Enabled    bool     `json:"enabled"`
	Direction  string   `json:"direction"`
	Groups     []string `json:"groups"`
	Username   string   `json:"username,omitempty"`
	Password   string   `json:"password,omitempty"`
	CertFile   string   `json:"certFile,omitempty"`
	CertPass   string   `json:"certPassword,omitempty"`
	TrustFile  string   `json:"trustFile,omitempty"`
	Insecure   bool     `json:"insecure,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
	NoPresence bool     `json:"noPresence,omitempty"`
}

type Config struct {
	Name           string           `json:"name"`
	Address        string           `json:"address"`
	ExtraNames     []string         `json:"extraNames"`
	Bind           string           `json:"bind"`
	NodeID         string           `json:"nodeId"`
	Ports          Ports            `json:"ports"`
	AllowAnonymous bool             `json:"allowAnonymous"`
	AnonymousGroup string           `json:"anonymousGroup"`
	Protobuf       bool             `json:"protobuf"`
	Replay         string           `json:"replay"`
	StrictGroups   bool             `json:"strictGroups"`
	Channels       bool             `json:"channels"`
	Mesh           MeshConfig       `json:"mesh"`
	Certificates   CertConfig       `json:"certificates"`
	Retention      RetentionConfig  `json:"retention"`
	Limits         LimitsConfig     `json:"limits"`
	Repeater       RepeaterConfig   `json:"repeater"`
	Federation     FederationConfig `json:"federation"`
	Peers          []PeerConfig     `json:"peers"`
	TileURL        string           `json:"tileUrl"`
	LogLevel       string           `json:"logLevel"`
	ACMEEmail      string           `json:"acmeEmail"`
	ACMEDomain     string           `json:"acmeDomain"`
}

func DefaultConfig() Config {
	return Config{
		Name: DefaultName,
		Ports: Ports{
			TCP:          8087,
			TCPAlt:       8088,
			TLS:          8089,
			UDP:          8087,
			HTTP:         8080,
			HTTPS:        8443,
			Enroll:       8446,
			WebSocket:    8090,
			Federation:   0,
			FederationV2: 0,
			API:          19023,
		},
		AllowAnonymous: true,
		AnonymousGroup: "__ANON__",
		Protobuf:       true,
		Replay:         "all",
		Channels:       true,
		Mesh: MeshConfig{
			Enabled: true,
			Send:    false,
			Groups:  []string{"239.2.3.1:6969", "224.10.10.1:17012"},
			TTL:     1,
		},
		Certificates: CertConfig{
			Organization: "TAK",
			Unit:         "TAK",
			Password:     "atakatak",
			KeyBits:      2048,
			ClientDays:   730,
			ServerDays:   825,
		},
		Retention: RetentionConfig{
			HistoryDays: 30,
			ChatDays:    7,
			FileDays:    0,
			MissionDays: 0,
		},
		Limits: LimitsConfig{
			MaxClients:      5000,
			MaxPerIP:        200,
			MaxMessageBytes: 8 << 20,
			MaxUploadMB:     1024,
			QueueLength:     4096,
			IdleTimeoutSec:  600,
			ReplayLimit:     5000,
			CacheLimit:      50000,
		},
		Repeater: RepeaterConfig{Enabled: true, IntervalSec: 5},
		Federation: FederationConfig{
			Groups:  []string{"__ANON__"},
			MaxHops: 4,
		},
		TileURL:  "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
		LogLevel: "info",
	}
}

func (c *Config) fill() {
	d := DefaultConfig()
	if c.Name == "" {
		c.Name = d.Name
	}
	if c.AnonymousGroup == "" {
		c.AnonymousGroup = d.AnonymousGroup
	}
	if c.Replay == "" {
		c.Replay = d.Replay
	}
	if c.Certificates.Organization == "" {
		c.Certificates.Organization = d.Certificates.Organization
	}
	if c.Certificates.Unit == "" {
		c.Certificates.Unit = d.Certificates.Unit
	}
	if c.Certificates.Password == "" {
		c.Certificates.Password = d.Certificates.Password
	}
	if c.Certificates.KeyBits < 2048 {
		c.Certificates.KeyBits = d.Certificates.KeyBits
	}
	if c.Certificates.ClientDays <= 0 {
		c.Certificates.ClientDays = d.Certificates.ClientDays
	}
	if c.Certificates.ServerDays <= 0 {
		c.Certificates.ServerDays = d.Certificates.ServerDays
	}
	if c.Limits.MaxClients <= 0 {
		c.Limits.MaxClients = d.Limits.MaxClients
	}
	if c.Limits.MaxPerIP <= 0 {
		c.Limits.MaxPerIP = d.Limits.MaxPerIP
	}
	if c.Limits.MaxMessageBytes < 64<<10 {
		c.Limits.MaxMessageBytes = d.Limits.MaxMessageBytes
	}
	if c.Limits.MaxUploadMB <= 0 {
		c.Limits.MaxUploadMB = d.Limits.MaxUploadMB
	}
	if c.Limits.QueueLength < 64 {
		c.Limits.QueueLength = d.Limits.QueueLength
	}
	if c.Limits.IdleTimeoutSec <= 0 {
		c.Limits.IdleTimeoutSec = d.Limits.IdleTimeoutSec
	}
	if c.Limits.ReplayLimit < 0 {
		c.Limits.ReplayLimit = 0
	}
	if c.Limits.CacheLimit <= 0 {
		c.Limits.CacheLimit = d.Limits.CacheLimit
	}
	if c.Repeater.IntervalSec <= 0 {
		c.Repeater.IntervalSec = d.Repeater.IntervalSec
	}
	if c.Mesh.TTL <= 0 {
		c.Mesh.TTL = 1
	}
	if c.Federation.MaxHops <= 0 {
		c.Federation.MaxHops = d.Federation.MaxHops
	}
	if len(c.Federation.Groups) == 0 {
		c.Federation.Groups = []string{c.AnonymousGroup}
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.NodeID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		c.NodeID = hex.EncodeToString(b)
	}
}

func SystemDataDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "GolangTAK")
	case "darwin":
		return "/Library/Application Support/GolangTAK"
	case "android", "ios", "plan9", "js", "wasip1":
		return ""
	}
	return "/var/lib/golangtak"
}

func userDataDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".golangtak")
	}
	return "golangtak-data"
}

func DefaultDataDir() string {
	if v := os.Getenv("GOLANGTAK_DATA"); v != "" {
		return v
	}
	system := SystemDataDir()
	switch {
	case system == "":
		return userDataDir()
	case runtime.GOOS == "windows" || os.Geteuid() == 0:
		return system
	}
	if _, err := os.Stat(system); err == nil {
		return system
	}
	return userDataDir()
}

func ConfigPath(dir string) string { return filepath.Join(dir, "config.json") }

func LoadConfig(dir string) (Config, error) {
	cfg := DefaultConfig()
	b, err := os.ReadFile(ConfigPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		cfg.fill()
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	b = []byte(strings.TrimPrefix(string(b), "\ufeff"))
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, errors.New("config.json is not valid JSON: " + err.Error())
	}
	cfg.fill()
	return cfg, nil
}

func SaveConfig(dir string, cfg Config) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(ConfigPath(dir), append(b, '\n'), 0o600)
}

func PrimaryIP() string {
	for _, target := range []string{"8.8.8.8:53", "1.1.1.1:53", "[2001:4860:4860::8888]:53"} {
		c, err := net.Dial("udp", target)
		if err != nil {
			continue
		}
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		if ip != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
			return ip.String()
		}
	}
	if ips := LocalIPs(); len(ips) > 0 {
		return ips[0]
	}
	return "127.0.0.1"
}

func LocalIPs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.IsLinkLocalUnicast() || ipn.IP.IsLoopback() {
				continue
			}
			out = append(out, ipn.IP.String())
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return strings.Contains(out[i], ".") && !strings.Contains(out[j], ".")
	})
	return out
}

func HostForURL(h string) string {
	if strings.Contains(h, ":") && !strings.HasPrefix(h, "[") {
		return "[" + h + "]"
	}
	return h
}
