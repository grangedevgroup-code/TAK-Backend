package takproto

const (
	BlobEmpty = 0
	BlobOther = 1
	BlobImage = 2
)

const (
	ConnFederationHubServer = 0
	ConnFederationHubClient = 1
	ConnFederationTakServer = 2
	ConnFederationTakClient = 3
)

const (
	HealthUnknown      = 0
	HealthServing      = 1
	HealthNotServing   = 2
	HealthNotConnected = 3
)

type Blob struct {
	Type        int
	Data        []byte
	Filename    string
	Timestamp   int64
	Description string
	Provenance  []Provenance
	MaxHops     int64
	CurrentHops int64
}

type Identity struct {
	Name        string
	UID         string
	Description string
	Type        int
	ServerID    string
}

type ServerVersion struct {
	Major, Minor, Patch int64
	Branch, Variant     string
}

type Subscription struct {
	Identity      Identity
	Filter        string
	ServerVersion *ServerVersion
}

type FederateGroups struct {
	Health      int
	HasHealth   bool
	Groups      []string
	Provenance  []Provenance
	MaxHops     int64
	CurrentHops int64
}

type ROL struct {
	Program     string
	Payload     []Blob
	Groups      []string
	Provenance  []Provenance
	MaxHops     int64
	CurrentHops int64
}

func appendProvenance(b []byte, field int, list []Provenance) []byte {
	for _, p := range list {
		var pb []byte
		pb = appendString(pb, 1, p.ServerID)
		pb = appendString(pb, 2, p.ServerName)
		b = appendBytes(b, field, pb)
	}
	return b
}

func appendHops(b []byte, field int, maxHops, current int64) []byte {
	if maxHops == 0 && current == 0 {
		return b
	}
	var hb []byte
	hb = appendInt(hb, 1, maxHops)
	hb = appendInt(hb, 2, current)
	return appendBytes(b, field, hb)
}

func readProvenance(b []byte) (Provenance, error) {
	var p Provenance
	err := eachField(b, func(g field) error {
		switch g.num {
		case 1:
			p.ServerID = g.str()
		case 2:
			p.ServerName = g.str()
		}
		return nil
	})
	return p, err
}

func readHops(b []byte) (int64, int64, error) {
	var maxHops, current int64
	err := eachField(b, func(g field) error {
		switch g.num {
		case 1:
			maxHops = int64(g.uint())
		case 2:
			current = int64(g.uint())
		}
		return nil
	})
	return maxHops, current, err
}

func MarshalBlob(bl Blob) []byte {
	var b []byte
	b = appendInt(b, 1, int64(bl.Type))
	if len(bl.Data) > 0 {
		b = appendBytes(b, 2, bl.Data)
	}
	b = appendString(b, 3, bl.Filename)
	b = appendInt(b, 4, bl.Timestamp)
	b = appendString(b, 5, bl.Description)
	b = appendProvenance(b, 6, bl.Provenance)
	b = appendHops(b, 7, bl.MaxHops, bl.CurrentHops)
	return b
}

func UnmarshalBlob(b []byte) (Blob, error) {
	var bl Blob
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			bl.Type = int(f.uint())
		case 2:
			bl.Data = append([]byte(nil), f.bytes...)
		case 3:
			bl.Filename = f.str()
		case 4:
			bl.Timestamp = int64(f.uint())
		case 5:
			bl.Description = f.str()
		case 6:
			p, err := readProvenance(f.bytes)
			if err != nil {
				return err
			}
			bl.Provenance = append(bl.Provenance, p)
		case 7:
			var err error
			if bl.MaxHops, bl.CurrentHops, err = readHops(f.bytes); err != nil {
				return err
			}
		}
		return nil
	})
	return bl, err
}

func MarshalIdentity(id Identity) []byte {
	var b []byte
	b = appendString(b, 1, id.Name)
	b = appendString(b, 2, id.UID)
	b = appendString(b, 3, id.Description)
	b = appendInt(b, 4, int64(id.Type))
	b = appendString(b, 5, id.ServerID)
	return b
}

func UnmarshalIdentity(b []byte) (Identity, error) {
	var id Identity
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			id.Name = f.str()
		case 2:
			id.UID = f.str()
		case 3:
			id.Description = f.str()
		case 4:
			id.Type = int(f.uint())
		case 5:
			id.ServerID = f.str()
		}
		return nil
	})
	return id, err
}

func MarshalSubscription(s Subscription) []byte {
	var b []byte
	b = appendBytes(b, 1, MarshalIdentity(s.Identity))
	b = appendString(b, 2, s.Filter)
	if v := s.ServerVersion; v != nil {
		var vb []byte
		vb = appendInt(vb, 1, v.Major)
		vb = appendInt(vb, 2, v.Minor)
		vb = appendInt(vb, 3, v.Patch)
		vb = appendString(vb, 4, v.Branch)
		vb = appendString(vb, 5, v.Variant)
		b = appendBytes(b, 3, vb)
	}
	return b
}

func UnmarshalSubscription(b []byte) (Subscription, error) {
	var s Subscription
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			id, err := UnmarshalIdentity(f.bytes)
			if err != nil {
				return err
			}
			s.Identity = id
		case 2:
			s.Filter = f.str()
		case 3:
			v := &ServerVersion{}
			if err := eachField(f.bytes, func(g field) error {
				switch g.num {
				case 1:
					v.Major = int64(g.uint())
				case 2:
					v.Minor = int64(g.uint())
				case 3:
					v.Patch = int64(g.uint())
				case 4:
					v.Branch = g.str()
				case 5:
					v.Variant = g.str()
				}
				return nil
			}); err != nil {
				return err
			}
			s.ServerVersion = v
		}
		return nil
	})
	return s, err
}

func MarshalHealth(status int) []byte {
	return appendInt(nil, 1, int64(status))
}

func UnmarshalHealth(b []byte) (int, error) {
	status := 0
	err := eachField(b, func(f field) error {
		if f.num == 1 {
			status = int(f.uint())
		}
		return nil
	})
	return status, err
}

func MarshalFederateGroups(g FederateGroups) []byte {
	var b []byte
	if g.HasHealth {
		b = appendBytes(b, 1, MarshalHealth(g.Health))
	}
	b = appendRepeated(b, 2, g.Groups)
	b = appendProvenance(b, 3, g.Provenance)
	b = appendHops(b, 4, g.MaxHops, g.CurrentHops)
	return b
}

func UnmarshalFederateGroups(b []byte) (FederateGroups, error) {
	var g FederateGroups
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			h, err := UnmarshalHealth(f.bytes)
			if err != nil {
				return err
			}
			g.Health, g.HasHealth = h, true
		case 2:
			g.Groups = append(g.Groups, f.str())
		case 3:
			p, err := readProvenance(f.bytes)
			if err != nil {
				return err
			}
			g.Provenance = append(g.Provenance, p)
		case 4:
			var err error
			if g.MaxHops, g.CurrentHops, err = readHops(f.bytes); err != nil {
				return err
			}
		}
		return nil
	})
	return g, err
}

func MarshalROL(r ROL) []byte {
	var b []byte
	b = appendString(b, 1, r.Program)
	for _, p := range r.Payload {
		b = appendBytes(b, 2, MarshalBlob(p))
	}
	b = appendRepeated(b, 3, r.Groups)
	b = appendProvenance(b, 4, r.Provenance)
	b = appendHops(b, 5, r.MaxHops, r.CurrentHops)
	return b
}

func UnmarshalROL(b []byte) (ROL, error) {
	var r ROL
	err := eachField(b, func(f field) error {
		switch f.num {
		case 1:
			r.Program = f.str()
		case 2:
			bl, err := UnmarshalBlob(f.bytes)
			if err != nil {
				return err
			}
			r.Payload = append(r.Payload, bl)
		case 3:
			r.Groups = append(r.Groups, f.str())
		case 4:
			p, err := readProvenance(f.bytes)
			if err != nil {
				return err
			}
			r.Provenance = append(r.Provenance, p)
		case 5:
			var err error
			if r.MaxHops, r.CurrentHops, err = readHops(f.bytes); err != nil {
				return err
			}
		}
		return nil
	})
	return r, err
}

func MarshalToken(token string) []byte {
	return appendString(nil, 1, token)
}
