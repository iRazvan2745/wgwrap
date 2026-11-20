package natpmp

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// fakeGateway answers each request with the given result code and public port 51234.
func fakeGateway(t *testing.T, rc byte) netip.AddrPort {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 64)
		for {
			n, from, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			want := []byte{0, buf[1], 0, 0, 0, 0, 0, 1, 0, 0, 0, 60}
			if n != 12 || !bytes.Equal(buf[:n], want) || (buf[1] != 1 && buf[1] != 2) {
				t.Errorf("request % x, want % x", buf[:n], want)
				return
			}
			resp := []byte{0, 128 + buf[1], 0, rc, 0, 0, 0, 9, 0, 0, 0xc8, 0x22, 0, 0, 0, 60}
			_, _ = pc.WriteToUDP(resp, from)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestMap(t *testing.T) {
	gw := fakeGateway(t, 0)
	for _, tcp := range []bool{false, true} {
		port, err := Map(gw, tcp, 60*time.Second)
		if err != nil || port != 51234 {
			t.Errorf("tcp=%v: got %d, %v; want 51234", tcp, port, err)
		}
	}

	if _, err := Map(fakeGateway(t, 3), true, 60*time.Second); err == nil || !strings.Contains(err.Error(), "result code 3") {
		t.Errorf("refused mapping: got %v", err)
	}
}
