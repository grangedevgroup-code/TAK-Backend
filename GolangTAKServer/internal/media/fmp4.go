package media

import (
	"encoding/binary"
)

func box(typ string, parts ...[]byte) []byte {
	n := 8
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 8, n)
	binary.BigEndian.PutUint32(out, uint32(n))
	copy(out[4:], typ)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func fullBox(typ string, version byte, flags uint32, parts ...[]byte) []byte {
	h := []byte{version, byte(flags >> 16), byte(flags >> 8), byte(flags)}
	return box(typ, append([][]byte{h}, parts...)...)
}

func u16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

var unityMatrix = cat(u32(0x00010000), u32(0), u32(0), u32(0), u32(0x00010000), u32(0), u32(0), u32(0), u32(0x40000000))

func avcC(sps, pps []byte) []byte {
	return box("avcC", []byte{1, sps[1], sps[2], sps[3], 0xff, 0xe1}, u16(uint16(len(sps))), sps, []byte{1}, u16(uint16(len(pps))), pps)
}

func InitSegment(sps, pps []byte, info SPSInfo, timescale uint32) []byte {
	w, h := uint16(info.Width), uint16(info.Height)
	ftyp := box("ftyp", []byte("iso5"), u32(512), []byte("iso5iso6mp41avc1"))
	mvhd := fullBox("mvhd", 0, 0, u32(0), u32(0), u32(1000), u32(0), u32(0x00010000), u16(0x0100), make([]byte, 10), unityMatrix, make([]byte, 24), u32(2))
	tkhd := fullBox("tkhd", 0, 3, u32(0), u32(0), u32(1), u32(0), u32(0), make([]byte, 8), u16(0), u16(0), u16(0), u16(0), unityMatrix, u32(uint32(w)<<16), u32(uint32(h)<<16))
	mdhd := fullBox("mdhd", 0, 0, u32(0), u32(0), u32(timescale), u32(0), u16(0x55c4), u16(0))
	hdlr := fullBox("hdlr", 0, 0, u32(0), []byte("vide"), make([]byte, 12), []byte("VideoHandler\x00"))
	vmhd := fullBox("vmhd", 0, 1, make([]byte, 8))
	dref := fullBox("dref", 0, 0, u32(1), fullBox("url ", 0, 1))
	dinf := box("dinf", dref)
	avc1 := box("avc1", make([]byte, 6), u16(1), make([]byte, 16), u16(w), u16(h), u32(0x00480000), u32(0x00480000), u32(0), u16(1), make([]byte, 32), u16(0x18), u16(0xffff), avcC(sps, pps))
	stsd := fullBox("stsd", 0, 0, u32(1), avc1)
	stbl := box("stbl", stsd, fullBox("stts", 0, 0, u32(0)), fullBox("stsc", 0, 0, u32(0)), fullBox("stsz", 0, 0, u32(0), u32(0)), fullBox("stco", 0, 0, u32(0)))
	minf := box("minf", vmhd, dinf, stbl)
	mdia := box("mdia", mdhd, hdlr, minf)
	trak := box("trak", tkhd, mdia)
	trex := fullBox("trex", 0, 0, u32(1), u32(1), u32(0), u32(0), u32(0))
	mvex := box("mvex", trex)
	moov := box("moov", mvhd, trak, mvex)
	return cat(ftyp, moov)
}

type Sample struct {
	Data     []byte
	Duration uint32
	Key      bool
}

func Fragment(seq uint32, baseTime uint64, samples []Sample) []byte {
	const trunFlags = 0x000001 | 0x000100 | 0x000200 | 0x000400
	var entries []byte
	total := 0
	for _, s := range samples {
		flags := uint32(0x01010000)
		if s.Key {
			flags = 0x02000000
		}
		entries = append(entries, cat(u32(s.Duration), u32(uint32(len(s.Data))), u32(flags))...)
		total += len(s.Data)
	}
	build := func(offset uint32) []byte {
		mfhd := fullBox("mfhd", 0, 0, u32(seq))
		tfhd := fullBox("tfhd", 0, 0x020000, u32(1))
		tfdt := fullBox("tfdt", 1, 0, u64(baseTime))
		trun := fullBox("trun", 0, trunFlags, u32(uint32(len(samples))), u32(offset), entries)
		return box("moof", mfhd, box("traf", tfhd, tfdt, trun))
	}
	moof := build(0)
	moof = build(uint32(len(moof) + 8))
	mdat := make([]byte, 8, 8+total)
	binary.BigEndian.PutUint32(mdat, uint32(8+total))
	copy(mdat[4:], "mdat")
	for _, s := range samples {
		mdat = append(mdat, s.Data...)
	}
	return cat(moof, mdat)
}

func AVCCSample(nalus [][]byte) []byte {
	n := 0
	for _, u := range nalus {
		n += 4 + len(u)
	}
	out := make([]byte, 0, n)
	for _, u := range nalus {
		out = binary.BigEndian.AppendUint32(out, uint32(len(u)))
		out = append(out, u...)
	}
	return out
}
