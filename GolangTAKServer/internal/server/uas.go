package server

import (
	"strconv"
	"strings"
	"time"

	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/cot"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/klv"
	"github.com/grangedevgroup-code/TAK-Backend/GolangTAKServer/internal/media"
)

const uasType = "a-f-A-M-F-Q"

func uasUID(path string) string { return "uas-" + strings.ReplaceAll(path, "/", "-") }

func ff(v float64, prec int) string { return strconv.FormatFloat(v, 'f', prec, 64) }

func (s *Server) onStreamMetadata(st *media.Stream, data []byte) {
	if s.Config().Video.HideUAS {
		return
	}
	var last *klv.UAS
	for _, pkt := range klv.FindAll(data) {
		if u, err := klv.Parse(pkt); err == nil {
			last = u
		}
	}
	if last == nil || !last.HasSensor {
		return
	}
	now := time.Now()
	if prev, ok := s.uasSeen.Load(st.Name); ok && now.Sub(prev.(time.Time)) < time.Second {
		return
	}
	s.uasSeen.Store(st.Name, now)
	groups := s.metadataGroups(st)
	for _, e := range s.uasEvents(st.Name, last) {
		m := NewMessage(e, nil, nil)
		if len(groups) == 0 {
			m.Everyone = true
		} else {
			m.Groups = s.dir.Mask(groups)
		}
		s.hub.Publish(m)
	}
}

func (s *Server) metadataGroups(st *media.Stream) []string {
	if v, ok := st.Meta("groups"); ok {
		return v.([]string)
	}
	for _, src := range s.Config().Video.Sources {
		if p, _ := media.CleanPath(firstNonEmpty(src.Path, src.Name)); p == st.Name {
			return src.Groups
		}
	}
	return nil
}

func (s *Server) uasEvents(path string, u *klv.UAS) []*cot.Event {
	cfg := s.Config()
	uid := uasUID(path)
	name := firstNonEmpty(u.Name(), path)
	stale := 15 * time.Second

	p := cot.New(uid, uasType, "m-g", stale)
	p.Point.Lat, p.Point.Lon = u.SensorLat, u.SensorLon
	switch {
	case u.HasHAE:
		p.Point.Hae = u.SensorHAE
	case u.HasAlt:
		p.Point.Hae = u.SensorAlt
	}
	p.Point.Ce, p.Point.Le = 10, 10
	p.Detail.AddNew("contact", "callsign", name)
	if u.HasHeading {
		tr := p.Detail.AddNew("track", "course", ff(u.Heading, 1))
		if u.HasGroundSpeed {
			tr.SetAttr("speed", ff(u.GroundSpeed, 1))
		}
	}
	if cfg.Video.RTSPPort > 0 {
		p.Detail.AddNew("__video", "url", s.rtspURL(nil, path), "uid", streamFeedUID(path))
	}
	if u.HasFOV {
		sn := p.Detail.AddNew("sensor", "type", "r-e", "version", "0.6", "fov", ff(u.HFOV, 2), "vfov", ff(u.VFOV, 2),
			"azimuth", ff(u.SensorAzimuth(), 1), "north", "0", "fovAlpha", "0.3", "fovRed", "1", "fovGreen", "1", "fovBlue", "1", "strokeColor", "-1", "strokeWeight", "1", "hideFov", "false", "displayMagneticReference", "0")
		if u.HasRelElev {
			sn.SetAttr("elevation", ff(u.SensorRelElev+u.Pitch, 1))
		}
		if u.HasSlant {
			sn.SetAttr("range", ff(u.SlantRange, 0))
		}
		sn.SetAttr("roll", ff(u.SensorRelRoll, 1))
		if u.SensorName != "" {
			sn.SetAttr("model", u.SensorName)
		}
	}
	p.Detail.AddNew("remarks").Text = "Drone telemetry from video " + path
	out := []*cot.Event{p}

	if u.HasFrame {
		spi := cot.New(uid+"-spi", "b-m-p-s-p-i", "m-g", stale)
		spi.Point.Lat, spi.Point.Lon = u.FrameLat, u.FrameLon
		if u.HasFrameElevation {
			spi.Point.Hae = u.FrameElev
		}
		spi.Detail.AddNew("contact", "callsign", name+" SPI")
		spi.Detail.AddNew("link", "uid", uid, "type", uasType, "relation", "p-p", "parent_callsign", name)
		spi.Detail.AddNew("precisionlocation", "geopointsrc", "Calc", "altsrc", "Calc")
		out = append(out, spi)
	}

	if len(u.Corners) == 4 {
		fp := cot.New(uid+"-footprint", "u-d-f", "h-e", stale)
		var lat, lon float64
		for _, c := range u.Corners {
			lat += c.Lat / 4
			lon += c.Lon / 4
		}
		fp.Point.Lat, fp.Point.Lon = lat, lon
		fp.Detail.AddNew("contact", "callsign", name+" footprint")
		for _, c := range append(u.Corners, u.Corners[0]) {
			fp.Detail.AddNew("link", "point", ff(c.Lat, 7)+","+ff(c.Lon, 7))
		}
		fp.Detail.AddNew("strokeColor", "value", "-256")
		fp.Detail.AddNew("strokeWeight", "value", "2")
		fp.Detail.AddNew("fillColor", "value", "855703296")
		fp.Detail.AddNew("labels_on", "value", "false")
		out = append(out, fp)
	}
	return out
}
