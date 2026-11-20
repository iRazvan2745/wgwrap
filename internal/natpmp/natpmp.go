// Package natpmp requests port mappings from a NAT-PMP gateway (RFC 6886), such as a VPN
// provider's server reached through the tunnel.
package natpmp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Port is the NAT-PMP server port.
const Port = 5351

// Map asks the gateway for a mapping and returns the public port it assigned. It sends what
// `natpmpc -a 1 0 <proto> <lifetime>` sends (the form Proton VPN documents): private port 0,
// suggested public port 1, so the gateway picks the port. Repeating the request before the
// lifetime ends renews the mapping.
func Map(gw netip.AddrPort, tcp bool, lifetime time.Duration) (uint16, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(gw))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	op := byte(1) // UDP
	if tcp {
		op = 2
	}
	req := []byte{0, op, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(req[8:], uint32(lifetime/time.Second))

	resp := make([]byte, 16)
	// RFC 6886 retransmits starting at 250ms, doubling each time.
	for timeout := 250 * time.Millisecond; timeout <= 2*time.Second; timeout *= 2 {
		if _, err := conn.Write(req); err != nil {
			return 0, err
		}
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		n, err := conn.Read(resp)
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n < 16 || resp[0] != 0 || resp[1] != 128+op {
			return 0, fmt.Errorf("malformed NAT-PMP response from %s", gw)
		}
		if rc := binary.BigEndian.Uint16(resp[2:]); rc != 0 {
			return 0, fmt.Errorf("NAT-PMP gateway %s refused the mapping (result code %d)", gw, rc)
		}
		return binary.BigEndian.Uint16(resp[10:]), nil
	}
	return 0, fmt.Errorf("no NAT-PMP response from %s", gw)
}
