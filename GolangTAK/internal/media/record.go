package media

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type recSample struct {
	size uint32
	dur  uint32
	key  bool
}

type MP4Writer struct {
	path    string
	data    *os.File
	sps     []byte
	pps     []byte
	info    SPSInfo
	samples []recSample
	bytes   uint64
	total   uint64
}

func NewMP4Writer(path string, sps, pps []byte, info SPSInfo) (*MP4Writer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".recording-*")
	if err != nil {
		return nil, err
	}
	return &MP4Writer{path: path, data: f, sps: sps, pps: pps, info: info}, nil
}

func (w *MP4Writer) Bytes() uint64 { return w.bytes }

func (w *MP4Writer) Duration() float64 { return float64(w.total) / liveTimescale }

func boxes(b []byte, fn func(typ string, body []byte) error) error {
	for len(b) >= 8 {
		size := int(binary.BigEndian.Uint32(b))
		typ := string(b[4:8])
		hdr := 8
		if size == 1 {
			if len(b) < 16 {
				return errors.New("bad box")
			}
			size, hdr = int(binary.BigEndian.Uint64(b[8:])), 16
		}
		if size < hdr || size > len(b) {
			return errors.New("bad box size")
		}
		if err := fn(typ, b[hdr:size]); err != nil {
			return err
		}
		b = b[size:]
	}
	return nil
}

func (w *MP4Writer) WriteFragment(frag []byte) error {
	var entries []recSample
	var mdat []byte
	err := boxes(frag, func(typ string, body []byte) error {
		switch typ {
		case "moof":
			return boxes(body, func(t string, b []byte) error {
				if t != "traf" {
					return nil
				}
				return boxes(b, func(t string, b []byte) error {
					if t != "trun" || len(b) < 8 {
						return nil
					}
					flags := uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
					count := int(binary.BigEndian.Uint32(b[4:]))
					p := b[8:]
					if flags&0x1 != 0 {
						p = p[4:]
					}
					if flags&0x4 != 0 {
						p = p[4:]
					}
					for i := 0; i < count; i++ {
						var s recSample
						if flags&0x100 != 0 {
							s.dur, p = binary.BigEndian.Uint32(p), p[4:]
						}
						if flags&0x200 != 0 {
							s.size, p = binary.BigEndian.Uint32(p), p[4:]
						}
						if flags&0x400 != 0 {
							s.key, p = binary.BigEndian.Uint32(p)&0x00010000 == 0, p[4:]
						}
						if flags&0x800 != 0 {
							p = p[4:]
						}
						entries = append(entries, s)
					}
					return nil
				})
			})
		case "mdat":
			mdat = body
		}
		return nil
	})
	if err != nil {
		return err
	}
	var need uint64
	for _, e := range entries {
		need += uint64(e.size)
	}
	if need != uint64(len(mdat)) {
		return errors.New("fragment sizes do not match its data")
	}
	if _, err := w.data.Write(mdat); err != nil {
		return err
	}
	for _, e := range entries {
		w.samples = append(w.samples, e)
		w.bytes += uint64(e.size)
		w.total += uint64(e.dur)
	}
	return nil
}

func (w *MP4Writer) moov(dataOffset uint64) []byte {
	ts := uint32(liveTimescale)
	dur := w.total
	durMS := uint32(dur * 1000 / uint64(ts))
	mvhd := fullBox("mvhd", 0, 0, u32(0), u32(0), u32(1000), u32(durMS), u32(0x00010000), u16(0x0100), make([]byte, 10), unityMatrix, make([]byte, 24), u32(2))
	tkhd := fullBox("tkhd", 0, 3, u32(0), u32(0), u32(1), u32(0), u32(durMS), make([]byte, 8), u16(0), u16(0), u16(0), u16(0), unityMatrix, u32(uint32(w.info.Width)<<16), u32(uint32(w.info.Height)<<16))
	mdhd := fullBox("mdhd", 0, 0, u32(0), u32(0), u32(ts), u32(uint32(dur)), u16(0x55c4), u16(0))
	hdlr := fullBox("hdlr", 0, 0, u32(0), []byte("vide"), make([]byte, 12), []byte("VideoHandler\x00"))
	vmhd := fullBox("vmhd", 0, 1, make([]byte, 8))
	dinf := box("dinf", fullBox("dref", 0, 0, u32(1), fullBox("url ", 0, 1)))
	avc1 := box("avc1", make([]byte, 6), u16(1), make([]byte, 16), u16(uint16(w.info.Width)), u16(uint16(w.info.Height)), u32(0x00480000), u32(0x00480000), u32(0), u16(1), make([]byte, 32), u16(0x18), u16(0xffff), avcC(w.sps, w.pps))
	stsd := fullBox("stsd", 0, 0, u32(1), avc1)
	var stts []byte
	runs := 0
	for i := 0; i < len(w.samples); {
		j := i
		for j < len(w.samples) && w.samples[j].dur == w.samples[i].dur {
			j++
		}
		stts = append(stts, cat(u32(uint32(j-i)), u32(w.samples[i].dur))...)
		runs++
		i = j
	}
	var stss []byte
	keys := 0
	sizes := make([]byte, 0, 4*len(w.samples))
	for i, s := range w.samples {
		if s.key {
			stss = append(stss, u32(uint32(i+1))...)
			keys++
		}
		sizes = append(sizes, u32(s.size)...)
	}
	stbl := box("stbl", stsd,
		fullBox("stts", 0, 0, u32(uint32(runs)), stts),
		fullBox("stss", 0, 0, u32(uint32(keys)), stss),
		fullBox("stsc", 0, 0, u32(1), u32(1), u32(uint32(len(w.samples))), u32(1)),
		fullBox("stsz", 0, 0, u32(0), u32(uint32(len(w.samples))), sizes),
		fullBox("co64", 0, 0, u32(1), u64(dataOffset)))
	trak := box("trak", tkhd, box("mdia", mdhd, hdlr, box("minf", vmhd, dinf, stbl)))
	return box("moov", mvhd, trak)
}

func (w *MP4Writer) Close() error {
	defer os.Remove(w.data.Name())
	if len(w.samples) == 0 {
		w.data.Close()
		return errors.New("nothing was recorded")
	}
	ftyp := box("ftyp", []byte("isom"), u32(512), []byte("isomiso2avc1mp41"))
	mdatHdr := make([]byte, 16)
	binary.BigEndian.PutUint32(mdatHdr, 1)
	copy(mdatHdr[4:], "mdat")
	binary.BigEndian.PutUint64(mdatHdr[8:], w.bytes+16)
	moov := w.moov(0)
	offset := uint64(len(ftyp) + len(moov) + len(mdatHdr))
	moov = w.moov(offset)
	out, err := os.CreateTemp(filepath.Dir(w.path), ".final-*")
	if err != nil {
		w.data.Close()
		return err
	}
	defer os.Remove(out.Name())
	if _, err := out.Write(cat(ftyp, moov, mdatHdr)); err != nil {
		out.Close()
		w.data.Close()
		return err
	}
	if _, err := w.data.Seek(0, io.SeekStart); err != nil {
		out.Close()
		w.data.Close()
		return err
	}
	if _, err := io.Copy(out, w.data); err != nil {
		out.Close()
		w.data.Close()
		return err
	}
	w.data.Close()
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), w.path)
}

func (l *Live) Params() (sps, pps []byte, info SPSInfo, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.init == nil {
		return nil, nil, SPSInfo{}, false
	}
	return l.sps, l.pps, l.info, true
}
