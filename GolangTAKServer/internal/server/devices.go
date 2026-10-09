package server

import (
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/store"
)

type Device struct {
	UID        string    `json:"uid"`
	Callsign   string    `json:"callsign"`
	User       string    `json:"user,omitempty"`
	Team       string    `json:"team,omitempty"`
	Role       string    `json:"role,omitempty"`
	Platform   string    `json:"platform,omitempty"`
	Version    string    `json:"version,omitempty"`
	Device     string    `json:"device,omitempty"`
	OS         string    `json:"os,omitempty"`
	Phone      string    `json:"phone,omitempty"`
	Type       string    `json:"type,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Remote     string    `json:"remote,omitempty"`
	Lat        float64   `json:"lat"`
	Lon        float64   `json:"lon"`
	FirstSeen  time.Time `json:"firstSeen"`
	LastSeen   time.Time `json:"lastSeen"`
	LastStatus string    `json:"lastStatus"`
}

type Devices struct {
	mu    sync.Mutex
	db    *store.Collection[Device]
	live  map[string]Device
	dirty map[string]bool
}

func OpenDevices(dir string) (*Devices, error) {
	db, err := store.Open[Device](filepath.Join(dir, "devices.jsonl"), false)
	if err != nil {
		return nil, err
	}
	d := &Devices{db: db, live: map[string]Device{}, dirty: map[string]bool{}}
	for _, dev := range db.All() {
		if dev.LastStatus == "Connected" {
			dev.LastStatus = "Disconnected"
		}
		d.live[dev.UID] = dev
	}
	return d, nil
}

func (d *Devices) Seen(c *Client, status string) {
	info := c.Info()
	if info.UID == "" {
		return
	}
	now := time.Now().UTC()
	d.mu.Lock()
	dev, ok := d.live[info.UID]
	if !ok {
		dev.FirstSeen = now
	}
	dev.UID = info.UID
	dev.Callsign = firstNonEmpty(info.Callsign, dev.Callsign)
	if u := c.User(); u != "" {
		dev.User = u
	}
	dev.Team, dev.Role = firstNonEmpty(info.Team, dev.Team), firstNonEmpty(info.Role, dev.Role)
	dev.Platform, dev.Version = firstNonEmpty(info.Platform, dev.Platform), firstNonEmpty(info.Version, dev.Version)
	dev.Device, dev.OS = firstNonEmpty(info.Device, dev.Device), firstNonEmpty(info.OS, dev.OS)
	dev.Phone = firstNonEmpty(info.Phone, dev.Phone)
	dev.Type = firstNonEmpty(info.Type, dev.Type)
	dev.Kind, dev.Remote = c.Kind, c.Remote
	if info.Lat != 0 || info.Lon != 0 {
		dev.Lat, dev.Lon = info.Lat, info.Lon
	}
	dev.LastSeen = now
	changed := dev.LastStatus != status
	dev.LastStatus = status
	d.live[dev.UID] = dev
	d.dirty[dev.UID] = true
	d.mu.Unlock()
	if changed {
		d.Flush()
	}
}

func (d *Devices) Flush() {
	d.mu.Lock()
	var batch []Device
	for uid := range d.dirty {
		batch = append(batch, d.live[uid])
	}
	d.dirty = map[string]bool{}
	d.mu.Unlock()
	for _, dev := range batch {
		d.db.Put(dev.UID, dev)
	}
}

func (d *Devices) Get(uid string) (Device, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	dev, ok := d.live[uid]
	return dev, ok
}

func (d *Devices) ByCallsign(cs string) (Device, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var best Device
	found := false
	for _, dev := range d.live {
		if dev.Callsign == cs && (!found || dev.LastSeen.After(best.LastSeen)) {
			best, found = dev, true
		}
	}
	return best, found
}

func (d *Devices) All() []Device {
	d.mu.Lock()
	out := make([]Device, 0, len(d.live))
	for _, dev := range d.live {
		out = append(out, dev)
	}
	d.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

func (d *Devices) Delete(uid string) {
	d.mu.Lock()
	delete(d.live, uid)
	delete(d.dirty, uid)
	d.mu.Unlock()
	d.db.Delete(uid)
}

func (d *Devices) Prune(maxAge time.Duration) {
	cut := time.Now().Add(-maxAge)
	d.mu.Lock()
	var gone []string
	for uid, dev := range d.live {
		if dev.LastStatus != "Connected" && dev.LastSeen.Before(cut) {
			gone = append(gone, uid)
			delete(d.live, uid)
			delete(d.dirty, uid)
		}
	}
	d.mu.Unlock()
	for _, uid := range gone {
		d.db.Delete(uid)
	}
}

func (d *Devices) Close() {
	d.Flush()
	d.db.Close()
}
