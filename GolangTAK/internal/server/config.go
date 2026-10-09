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
	"strconv"
	"strings"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAK/internal/cot"
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

	NoMissions  bool `json:"disableMissionFederation"`
	AllowDelete bool `json:"allowFederatedDelete"`
}

type ADSBFeed struct {
	Enabled     bool    `json:"enabled"`
	URL         string  `json:"url"`
	APIKey      string  `json:"apiKey,omitempty"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	RadiusNM    float64 `json:"radiusNm"`
	IntervalSec int     `json:"intervalSec"`
	Group       string  `json:"group"`
}

type AISFeed struct {
	Enabled     bool    `json:"enabled"`
	Username    string  `json:"username"`
	South       float64 `json:"south"`
	West        float64 `json:"west"`
	North       float64 `json:"north"`
	East        float64 `json:"east"`
	MMSI        string  `json:"mmsi,omitempty"`
	IMO         string  `json:"imo,omitempty"`
	IntervalSec int     `json:"intervalSec"`
	Group       string  `json:"group"`
}

type LDAPConfig struct {
	Enabled           bool   `json:"enabled"`
	URL               string `json:"url"`
	StartTLS          bool   `json:"startTls"`
	Insecure          bool   `json:"insecure"`
	TrustFile         string `json:"trustFile,omitempty"`
	BindDN            string `json:"bindDn"`
	BindPassword      string `json:"bindPassword"`
	BaseDN            string `json:"baseDn"`
	UserFilter        string `json:"userFilter"`
	UserDN            string `json:"userDn"`
	GroupFilter       string `json:"groupFilter"`
	GroupBaseDN       string `json:"groupBaseDn"`
	GroupPrefix       string `json:"groupPrefix"`
	AdminGroup        string `json:"adminGroup"`
	CallsignAttribute string `json:"callsignAttribute"`
}

type MeshtasticChannel struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type MeshtasticConfig struct {
	Enabled         bool                `json:"enabled"`
	BrokerPort      int                 `json:"brokerPort"`
	BrokerAnonymous bool                `json:"brokerAnonymous"`
	Upstream        string              `json:"upstream"`
	Root            string              `json:"root"`
	Channels        []MeshtasticChannel `json:"channels"`
	Group           string              `json:"group"`
	Downlink        bool                `json:"downlink"`
	DownlinkChannel string              `json:"downlinkChannel"`
	NodeNum         uint32              `json:"nodeNum"`
	IntervalSec     int                 `json:"intervalSec"`
}

type FeedsConfig struct {
	ADSB ADSBFeed `json:"adsb"`
	AIS  AISFeed  `json:"ais"`
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
	Name           string            `json:"name"`
	Address        string            `json:"address"`
	ExtraNames     []string          `json:"extraNames"`
	Bind           string            `json:"bind"`
	NodeID         string            `json:"nodeId"`
	Ports          Ports             `json:"ports"`
	AllowAnonymous bool              `json:"allowAnonymous"`
	AnonymousGroup string            `json:"anonymousGroup"`
	Protobuf       bool              `json:"protobuf"`
	Replay         string            `json:"replay"`
	StrictGroups   bool              `json:"strictGroups"`
	Channels       bool              `json:"channels"`
	Mesh           MeshConfig        `json:"mesh"`
	Certificates   CertConfig        `json:"certificates"`
	Retention      RetentionConfig   `json:"retention"`
	Limits         LimitsConfig      `json:"limits"`
	Repeater       RepeaterConfig    `json:"repeater"`
	Federation     FederationConfig  `json:"federation"`
	Peers          []PeerConfig      `json:"peers"`
	Feeds          FeedsConfig       `json:"feeds"`
	LDAP           LDAPConfig        `json:"ldap"`
	Meshtastic     MeshtasticConfig  `json:"meshtastic"`
	Telegram       TelegramConfig    `json:"telegram"`
	Plugins        []PluginConfig    `json:"plugins"`
	DataFeeds      []DataFeedConfig  `json:"dataFeeds"`
	Video          VideoServerConfig `json:"videoServer"`
	Voice          VoiceConfig       `json:"voice"`
	Locate         LocateConfig      `json:"locate"`
	Email          EmailConfig       `json:"email"`
	ACME           ACMEConfig        `json:"letsEncrypt"`
	TileURL        string            `json:"tileUrl"`
	LogLevel       string            `json:"logLevel"`
	ACMEEmail      string            `json:"acmeEmail"`
	ACMEDomain     string            `json:"acmeDomain"`
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
		Video:    VideoServerConfig{Enabled: true, RTSPPort: 8554, RTMPPort: 1935, RTPPort: 8000, AnonymousRead: true, MaxStreams: 100, RecordMinutes: 30, RecordDays: 7},
		Voice:    VoiceConfig{Enabled: true, Port: 64738, MaxUsers: 200},
		Federation: FederationConfig{
			Groups:  []string{"__ANON__"},
			MaxHops: 4,
		},
		LDAP:     LDAPConfig{UserFilter: "(|(uid={user})(sAMAccountName={user})(userPrincipalName={user}))"},
		Telegram: TelegramConfig{Chat: true, Alerts: true, Locations: true},
		Meshtastic: MeshtasticConfig{
			BrokerPort:  1883,
			Root:        "msh/US",
			Channels:    []MeshtasticChannel{{Name: "LongFast", Key: "AQ=="}},
			IntervalSec: 60,
		},
		Feeds: FeedsConfig{
			ADSB: ADSBFeed{URL: "https://api.adsb.lol/v2/point", RadiusNM: 25, IntervalSec: 30},
			AIS:  AISFeed{South: -90, West: -180, North: 90, East: 180, IntervalSec: 120},
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
	for i := range c.DataFeeds {
		f := &c.DataFeeds[i]
		if f.UUID == "" {
			f.UUID = cot.NewUID()
		}
		if f.Name == "" {
			f.Name = "Data feed " + strconv.Itoa(i+1)
		}
		f.Protocol = strings.ToLower(firstNonEmpty(f.Protocol, "tcp"))
	}
	if len(c.Federation.Groups) == 0 {
		c.Federation.Groups = []string{c.AnonymousGroup}
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Meshtastic.Root == "" {
		c.Meshtastic.Root = d.Meshtastic.Root
	}
	if len(c.Meshtastic.Channels) == 0 {
		c.Meshtastic.Channels = d.Meshtastic.Channels
	}
	if c.Meshtastic.IntervalSec < 10 {
		c.Meshtastic.IntervalSec = d.Meshtastic.IntervalSec
	}
	if c.Meshtastic.NodeNum == 0 {
		var b [4]byte
		rand.Read(b[:])
		c.Meshtastic.NodeNum = (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) | 0x10000000
	}
	if c.Feeds.ADSB.URL == "" || strings.TrimRight(c.Feeds.ADSB.URL, "/") == "https://api.airplanes.live/v2/point" {
		c.Feeds.ADSB.URL = d.Feeds.ADSB.URL
	}
	if c.Feeds.ADSB.RadiusNM <= 0 {
		c.Feeds.ADSB.RadiusNM = d.Feeds.ADSB.RadiusNM
	}
	if c.Feeds.ADSB.IntervalSec < 5 {
		c.Feeds.ADSB.IntervalSec = d.Feeds.ADSB.IntervalSec
	}
	if c.Feeds.AIS.IntervalSec < 60 {
		c.Feeds.AIS.IntervalSec = d.Feeds.AIS.IntervalSec
	}
	if c.Feeds.AIS.South == 0 && c.Feeds.AIS.North == 0 && c.Feeds.AIS.West == 0 && c.Feeds.AIS.East == 0 {
		c.Feeds.AIS.South, c.Feeds.AIS.West, c.Feeds.AIS.North, c.Feeds.AIS.East = d.Feeds.AIS.South, d.Feeds.AIS.West, d.Feeds.AIS.North, d.Feeds.AIS.East
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
