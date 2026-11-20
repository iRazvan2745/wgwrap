package config

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

const (
	k1 = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	k2 = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
	k3 = "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="
)

func TestParseFull(t *testing.T) {
	in := `
# a comment
[interface]
PrivateKey = ` + k1 + `
Address = 10.0.0.2/24, fd00::2/64
address = 10.0.1.2      # repeated key, bare IP
DNS = 1.1.1.1, example.internal
MTU = 1380
ListenPort = 51000
FwMark = 0x1234
PostUp = iptables -A FORWARD
Table = auto

[Peer]
PublicKey = ` + k2 + `
PresharedKey = ` + k3 + `
Endpoint = [2001:db8::1]:51820
AllowedIPs = 10.0.0.0/24
AllowedIPs = 192.168.1.7/24, ::/0
PersistentKeepalive = 25

[PEER]
PublicKey = ` + k3 + `
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`
	c, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	wantAddr := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.2/24"),
		netip.MustParsePrefix("fd00::2/64"),
		netip.MustParsePrefix("10.0.1.2/32"),
	}
	if len(c.Addresses) != 3 || c.Addresses[0] != wantAddr[0] || c.Addresses[1] != wantAddr[1] || c.Addresses[2] != wantAddr[2] {
		t.Errorf("addresses = %v", c.Addresses)
	}
	if strings.Join(c.DNS, ",") != "1.1.1.1,example.internal" || c.MTU != 1380 || c.ListenPort != 51000 || c.FwMark != 0x1234 {
		t.Errorf("interface = %+v", c)
	}
	if len(c.Warnings) != 1 || !strings.Contains(c.Warnings[0], "line 11") {
		t.Errorf("warnings = %v", c.Warnings)
	}
	if len(c.Peers) != 2 {
		t.Fatalf("peers = %d", len(c.Peers))
	}
	p := c.Peers[0]
	if p.Endpoint != "[2001:db8::1]:51820" || p.PersistentKeepalive != 25*time.Second || p.PresharedKey != k3 {
		t.Errorf("peer0 = %+v", p)
	}
	// AllowedIPs accumulate across repeated keys and are masked to network form.
	if len(p.AllowedIPs) != 3 || p.AllowedIPs[1] != netip.MustParsePrefix("192.168.1.0/24") {
		t.Errorf("allowed = %v", p.AllowedIPs)
	}
	if c.Peers[1].Endpoint != "vpn.example.com:51820" || c.Peers[1].PublicKey != k3 {
		t.Errorf("peer1 = %+v", c.Peers[1])
	}
}

func TestParseTable(t *testing.T) {
	for v, want := range map[string][2]int{"off": {int(TableOff), 0}, "AUTO": {int(TableAuto), 0}, "1234": {int(TableNum), 1234}, "main": {int(TableNum), 254}} {
		c, err := Parse(strings.NewReader("[Interface]\nPrivateKey=" + k1 + "\nTable=" + v))
		if err != nil {
			t.Fatal(v, err)
		}
		if int(c.Table) != want[0] || c.TableID != want[1] {
			t.Errorf("Table=%s: got %v %v", v, c.Table, c.TableID)
		}
	}
}

func TestParseErrors(t *testing.T) {
	head := "[Interface]\nPrivateKey = " + k1 + "\n"
	cases := []struct{ in, want string }{
		{"[Interface]\nAddress = 10.0.0.1/24\n", "PrivateKey is missing"},
		{"[Interface]\nPrivateKey = nope\n", "line 2: PrivateKey is not a valid"},
		{head + "Address = 10.0.0.300/24\n", "line 3: Address"},
		{head + "MTU = big\n", "line 3: MTU"},
		{head + "Bogus = 1\n", `line 3: unknown [Interface] key "bogus"`},
		{head + "just text\n", "line 3: expected key = value"},
		{head + "PrivateKey " + k2 + "\n", "line 3: expected key = value"},
		{head + "PrivateKey " + strings.TrimRight(k2, "=") + "\n", "line 3: expected key = value"},
		{head + "[Server]\n", "line 3: unknown section"},
		{"Address = 10.0.0.1/24\n", "line 1: address outside of a section"},
		{head + "[Peer]\nAllowedIPs = 10.0.0.0/33\n", "line 4: AllowedIPs"},
		{head + "[Peer]\nPublicKey = " + k2 + "\nEndpoint = 2001:db8::1:51820\n", "line 5: Endpoint"},
		{head + "[Peer]\nPublicKey = " + k2 + "\nEndpoint = host:99999\n", "line 5: Endpoint"},
		{head + "[Peer]\nPublicKey = " + k2 + "\nPersistentKeepalive = -1\n", "line 5: PersistentKeepalive"},
		{head + "[Peer]\nAllowedIPs = 10.0.0.0/24\n", "line 3: [Peer] has no PublicKey"},
		{head + "Table = -3\n", "line 3: Table"},
		{head + "ListenPort = 70000\n", "line 3: ListenPort"},
	}
	for _, tc := range cases {
		_, err := Parse(strings.NewReader(tc.in))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q) err = %v, want %q", tc.in, err, tc.want)
		}
		if err != nil && (strings.Contains(strings.ToLower(err.Error()), strings.ToLower(k1[:20])) || strings.Contains(strings.ToLower(err.Error()), strings.ToLower(k2[:20]))) {
			t.Errorf("Parse(%q) error leaks a key: %v", tc.in, err)
		}
	}
}
