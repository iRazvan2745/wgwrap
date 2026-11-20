// Package config parses the wg-quick configuration format.
package config

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// TableMode is the value of [Interface] Table.
type TableMode int

const (
	TableAuto TableMode = iota // wg-quick default: routes in main, /0 via fwmark policy routing
	TableOff                   // add no routes at all
	TableNum                   // every route goes into Config.TableID, no policy rules
)

type Config struct {
	PrivateKey string
	Addresses  []netip.Prefix // host bits kept, e.g. 10.0.0.2/24
	DNS        []string       // IPs or search domains, as written
	MTU        int
	ListenPort int
	FwMark     uint32
	Table      TableMode
	TableID    int
	Peers      []Peer
	Warnings   []string
}

type Peer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string // host:port, host may be a name; resolved at runtime
	AllowedIPs          []netip.Prefix
	PersistentKeepalive time.Duration
	Line                int // line of the [Peer] header, for error messages
}

// lineErr is a parse error tied to a config line.
func lineErr(n int, f string, a ...any) error {
	return fmt.Errorf("line %d: %s", n, fmt.Sprintf(f, a...))
}

func splitList(v string) (out []string) {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func checkKey(n int, name, v string) error {
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil || len(b) != 32 {
		return lineErr(n, "%s is not a valid WireGuard key (want 44 chars of base64)", name)
	}
	return nil
}

// Parse reads a wg-quick config and validates it.
func Parse(r io.Reader) (*Config, error) {
	c := &Config{MTU: 1420}
	var p *Peer
	section := ""
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line, _, _ := strings.Cut(sc.Text(), "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			switch strings.ToLower(line) {
			case "[interface]":
				section, p = "interface", nil
			case "[peer]":
				section = "peer"
				c.Peers = append(c.Peers, Peer{Line: n})
				p = &c.Peers[len(c.Peers)-1]
			default:
				return nil, lineErr(n, "unknown section %s", line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, lineErr(n, "expected key = value, got %q", line)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		var err error
		switch section {
		case "interface":
			err = c.setInterface(n, k, v)
		case "peer":
			err = p.set(n, k, v)
		default:
			err = lineErr(n, "%s outside of a section", k)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if c.PrivateKey == "" {
		return nil, fmt.Errorf("[Interface] PrivateKey is missing")
	}
	for i := range c.Peers {
		if c.Peers[i].PublicKey == "" {
			return nil, lineErr(c.Peers[i].Line, "[Peer] has no PublicKey")
		}
	}
	return c, nil
}

func (c *Config) setInterface(n int, k, v string) error {
	switch k {
	case "privatekey":
		if err := checkKey(n, "PrivateKey", v); err != nil {
			return err
		}
		c.PrivateKey = v
	case "address":
		for _, a := range splitList(v) {
			pf, err := netip.ParsePrefix(a)
			if err != nil {
				// wg-quick accepts a bare IP and treats it as a host address.
				ip, ierr := netip.ParseAddr(a)
				if ierr != nil {
					return lineErr(n, "Address %q: %v", a, err)
				}
				pf = netip.PrefixFrom(ip, ip.BitLen())
			}
			c.Addresses = append(c.Addresses, pf)
		}
	case "dns":
		c.DNS = append(c.DNS, splitList(v)...)
	case "mtu":
		m, err := strconv.Atoi(v)
		if err != nil || m < 576 || m > 65535 {
			return lineErr(n, "MTU %q must be a number between 576 and 65535", v)
		}
		c.MTU = m
	case "listenport":
		port, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return lineErr(n, "ListenPort %q is not a valid port", v)
		}
		c.ListenPort = int(port)
	case "fwmark":
		if strings.EqualFold(v, "off") {
			c.FwMark = 0
			return nil
		}
		m, err := strconv.ParseUint(v, 0, 32) // accepts 0x... like wg(8)
		if err != nil {
			return lineErr(n, "FwMark %q is not a number", v)
		}
		c.FwMark = uint32(m)
	case "table":
		switch strings.ToLower(v) {
		case "off":
			c.Table = TableOff
		case "auto":
			c.Table = TableAuto
		case "main":
			c.Table, c.TableID = TableNum, 254
		default:
			t, err := strconv.ParseUint(v, 10, 32)
			if err != nil || t == 0 {
				return lineErr(n, "Table %q must be off, auto, main or a table number", v)
			}
			c.Table, c.TableID = TableNum, int(t)
		}
	case "preup", "postup", "predown", "postdown", "saveconfig":
		c.Warnings = append(c.Warnings, fmt.Sprintf("line %d: %s is ignored (no shell in the container)", n, k))
	default:
		return lineErr(n, "unknown [Interface] key %q", k)
	}
	return nil
}

func (p *Peer) set(n int, k, v string) error {
	switch k {
	case "publickey":
		if err := checkKey(n, "PublicKey", v); err != nil {
			return err
		}
		p.PublicKey = v
	case "presharedkey":
		if err := checkKey(n, "PresharedKey", v); err != nil {
			return err
		}
		p.PresharedKey = v
	case "endpoint":
		host, port, err := net.SplitHostPort(v)
		if err != nil || host == "" {
			return lineErr(n, "Endpoint %q must be host:port (use [addr]:port for IPv6)", v)
		}
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return lineErr(n, "Endpoint %q has an invalid port", v)
		}
		p.Endpoint = v
	case "allowedips":
		for _, a := range splitList(v) {
			pf, err := netip.ParsePrefix(a)
			if err != nil {
				return lineErr(n, "AllowedIPs %q: %v", a, err)
			}
			p.AllowedIPs = append(p.AllowedIPs, pf.Masked())
		}
	case "persistentkeepalive":
		if strings.EqualFold(v, "off") {
			p.PersistentKeepalive = 0
			return nil
		}
		s, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return lineErr(n, "PersistentKeepalive %q must be seconds or off", v)
		}
		p.PersistentKeepalive = time.Duration(s) * time.Second
	default:
		return lineErr(n, "unknown [Peer] key %q", k)
	}
	return nil
}
