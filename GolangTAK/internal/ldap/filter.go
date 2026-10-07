package ldap

import (
	"encoding/hex"
	"errors"
	"strings"
)

var errFilter = errors.New("ldap: invalid search filter")

func EscapeFilter(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '*', '(', ')', '\\', 0:
			b.WriteString(`\` + hex.EncodeToString([]byte{c}))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func EscapeDN(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ',' || c == '+' || c == '"' || c == '\\' || c == '<' || c == '>' || c == ';' || c == '=':
			b.WriteByte('\\')
			b.WriteByte(c)
		case (i == 0 && (c == ' ' || c == '#')) || (i == len(s)-1 && c == ' '):
			b.WriteByte('\\')
			b.WriteByte(c)
		case c == 0:
			b.WriteString(`\00`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func unescapeValue(s string) (string, error) {
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var b []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b = append(b, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", errFilter
		}
		v, err := hex.DecodeString(s[i+1 : i+3])
		if err != nil {
			return "", errFilter
		}
		b = append(b, v...)
		i += 2
	}
	return string(b), nil
}

func compileFilter(f string) ([]byte, error) {
	f = strings.TrimSpace(f)
	if f == "" {
		f = "(objectClass=*)"
	}
	if !strings.HasPrefix(f, "(") {
		f = "(" + f + ")"
	}
	out, rest, err := parseFilter(f)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(rest) != "" {
		return nil, errFilter
	}
	return out, nil
}

func parseFilter(f string) ([]byte, string, error) {
	if len(f) < 3 || f[0] != '(' {
		return nil, "", errFilter
	}
	f = f[1:]
	switch f[0] {
	case '&', '|':
		tag := byte(0xa0)
		if f[0] == '|' {
			tag = 0xa1
		}
		f = f[1:]
		var parts [][]byte
		for len(f) > 0 && f[0] == '(' {
			p, rest, err := parseFilter(f)
			if err != nil {
				return nil, "", err
			}
			parts = append(parts, p)
			f = rest
		}
		if len(f) == 0 || f[0] != ')' || len(parts) == 0 {
			return nil, "", errFilter
		}
		return seq(tag, parts...), f[1:], nil
	case '!':
		p, rest, err := parseFilter(f[1:])
		if err != nil {
			return nil, "", err
		}
		if len(rest) == 0 || rest[0] != ')' {
			return nil, "", errFilter
		}
		return seq(0xa2, p), rest[1:], nil
	}
	depth := 0
	end := -1
	for i := 0; i < len(f); i++ {
		if f[i] == '(' {
			depth++
		}
		if f[i] == ')' {
			if depth == 0 {
				end = i
				break
			}
			depth--
		}
	}
	if end < 0 {
		return nil, "", errFilter
	}
	item, rest := f[:end], f[end+1:]
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return nil, "", errFilter
	}
	attr, value := item[:eq], item[eq+1:]
	op := byte(0xa3)
	switch attr[len(attr)-1] {
	case '>':
		op, attr = 0xa5, attr[:len(attr)-1]
	case '<':
		op, attr = 0xa6, attr[:len(attr)-1]
	case '~':
		op, attr = 0xa8, attr[:len(attr)-1]
	}
	attr = strings.TrimSpace(attr)
	if attr == "" {
		return nil, "", errFilter
	}
	if op == 0xa3 && value == "*" {
		return encStr(0x87, attr), rest, nil
	}
	if op == 0xa3 && strings.Contains(value, "*") {
		pieces := strings.Split(value, "*")
		var subs [][]byte
		for i, p := range pieces {
			if p == "" {
				continue
			}
			v, err := unescapeValue(p)
			if err != nil {
				return nil, "", err
			}
			tag := byte(0x81)
			if i == 0 {
				tag = 0x80
			} else if i == len(pieces)-1 {
				tag = 0x82
			}
			subs = append(subs, encStr(tag, v))
		}
		return seq(0xa4, encStr(tagOctetString, attr), seq(tagSequence, subs...)), rest, nil
	}
	v, err := unescapeValue(value)
	if err != nil {
		return nil, "", err
	}
	return seq(op, encStr(tagOctetString, attr), encStr(tagOctetString, v)), rest, nil
}
