package server

import (
	"archive/zip"
	"encoding/binary"
	"io"
	"strconv"
	"unicode/utf16"
)

type apkMeta struct {
	Package string
	Version string
	Code    string
	MinSDK  string
	Label   string
}

func apkInfo(path string) apkMeta {
	var meta apkMeta
	zr, err := zip.OpenReader(path)
	if err != nil {
		return meta
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "AndroidManifest.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return meta
		}
		data, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		rc.Close()
		if err != nil {
			return meta
		}
		parseAXML(data, &meta)
		return meta
	}
	return meta
}

func parseAXML(b []byte, meta *apkMeta) {
	u16 := func(off int) int {
		if off+2 > len(b) {
			return 0
		}
		return int(binary.LittleEndian.Uint16(b[off:]))
	}
	u32 := func(off int) int {
		if off+4 > len(b) {
			return 0
		}
		return int(binary.LittleEndian.Uint32(b[off:]))
	}
	if len(b) < 8 || u16(0) != 0x0003 {
		return
	}
	var strs []string
	off := u16(2)
	for off+8 <= len(b) {
		typ, hsize, size := u16(off), u16(off+2), u32(off+4)
		if size < 8 || off+size > len(b) {
			return
		}
		switch typ {
		case 0x0001:
			count := u32(off + 8)
			flags := u32(off + 16)
			strStart := u32(off + 20)
			utf8 := flags&0x100 != 0
			if count > 100000 {
				return
			}
			for i := 0; i < count; i++ {
				so := off + strStart + u32(off+hsize+i*4)
				strs = append(strs, readAXMLString(b, so, utf8))
			}
		case 0x0102:
			name := u32(off + 20)
			attrStart := u16(off + 24)
			attrSize := u16(off + 26)
			attrCount := u16(off + 28)
			if attrSize == 0 {
				attrSize = 20
			}
			el := ""
			if name >= 0 && name < len(strs) {
				el = strs[name]
			}
			for i := 0; i < attrCount; i++ {
				a := off + 16 + attrStart + i*attrSize
				if a+20 > len(b) {
					break
				}
				an := u32(a + 4)
				raw := u32(a + 8)
				dtype := int(b[a+15])
				data := u32(a + 16)
				attr := ""
				if an >= 0 && an < len(strs) {
					attr = strs[an]
				}
				val := ""
				switch {
				case raw >= 0 && raw < len(strs) && uint32(raw) != 0xffffffff:
					val = strs[raw]
				case dtype == 0x10 || dtype == 0x11:
					val = strconv.Itoa(int(int32(uint32(data))))
				case dtype == 0x03 && data >= 0 && data < len(strs):
					val = strs[data]
				}
				switch {
				case el == "manifest" && attr == "package":
					meta.Package = val
				case el == "manifest" && attr == "versionName":
					meta.Version = val
				case el == "manifest" && attr == "versionCode":
					meta.Code = val
				case el == "uses-sdk" && attr == "minSdkVersion":
					meta.MinSDK = val
				case el == "application" && attr == "label" && dtype == 0x03:
					meta.Label = val
				}
			}
		}
		off += size
	}
}

func readAXMLString(b []byte, off int, utf8 bool) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	if utf8 {
		i := off + 1
		if b[off]&0x80 != 0 {
			i++
		}
		if i >= len(b) {
			return ""
		}
		l := int(b[i])
		i++
		if l&0x80 != 0 {
			if i >= len(b) {
				return ""
			}
			l = (l&0x7f)<<8 | int(b[i])
			i++
		}
		if i+l > len(b) {
			return ""
		}
		return string(b[i : i+l])
	}
	if off+2 > len(b) {
		return ""
	}
	l := int(binary.LittleEndian.Uint16(b[off:]))
	i := off + 2
	if l&0x8000 != 0 {
		if off+4 > len(b) {
			return ""
		}
		l = (l&0x7fff)<<16 | int(binary.LittleEndian.Uint16(b[off+2:]))
		i = off + 4
	}
	if i+l*2 > len(b) {
		return ""
	}
	u := make([]uint16, l)
	for k := 0; k < l; k++ {
		u[k] = binary.LittleEndian.Uint16(b[i+2*k:])
	}
	return string(utf16.Decode(u))
}
