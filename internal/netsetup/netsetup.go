// Package netsetup creates and configures the WireGuard interface inside the current
// network namespace, with the same routing semantics as wg-quick.
package netsetup

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"pkg.bar/wgwrap/internal/config"
	"pkg.bar/wgwrap/internal/userspace"
)

const defaultMark = 51820

// Logging hooks, set by the caller.
var (
	Infof  = func(string, ...any) {}
	Warnf  = func(string, ...any) {}
	Debugf = func(string, ...any) {}
)

type Options struct {
	Iface          string
	Mode           string // auto, kernel, userspace
	ResolveTimeout time.Duration
	Debug          bool
	AllowDNSLeak   bool // full tunnel may keep using Docker's host-side resolver
}

// Tunnel is the result of Up. Userspace is nil in kernel mode.
type Tunnel struct {
	Iface      string
	Mode       string
	Userspace  *userspace.Device
	FullTunnel bool // policy routing sends all egress into the tunnel
}

// Up creates the interface, configures keys/peers, addresses, routes, rules and DNS.
func Up(c *config.Config, o Options) (*Tunnel, error) {
	t := &Tunnel{Iface: o.Iface}
	if _, full := routingPlan(c, true); len(full) > 0 && len(c.DNS) == 0 && !o.AllowDNSLeak {
		if ns := loopbackNameserver("/etc/resolv.conf"); ns != "" {
			return nil, fmt.Errorf("full tunnel without DNS=: queries to Docker's resolver %s are forwarded by the host, outside the tunnel. "+
				"Set DNS = <resolver reachable through the tunnel> in [Interface], or WG_ALLOW_DNS_LEAK=1 to accept this", ns)
		}
	}
	if err := t.create(c, o); err != nil {
		return nil, err
	}
	link, err := netlink.LinkByName(o.Iface)
	if err != nil {
		return nil, err
	}
	v6 := ipv6Enabled(o.Iface)
	if !v6 && hasV6(c) {
		Warnf("IPv6 is disabled in this container; skipping IPv6 addresses and routes (enable with --sysctl net.ipv6.conf.default.disable_ipv6=0)")
	}

	// Keys and peers, the same thing `wg setconf` does.
	mark, full := routingPlan(c, v6)
	cfg, err := deviceConfig(c, o.ResolveTimeout)
	if err != nil {
		return nil, err
	}
	if mark != 0 {
		cfg.FirewallMark = &mark
	}
	wg, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
	}
	defer wg.Close()
	if err := wg.ConfigureDevice(o.Iface, cfg); err != nil {
		return nil, fmt.Errorf("configure %s: %w", o.Iface, err)
	}

	for _, a := range c.Addresses {
		if a.Addr().Is6() && !v6 {
			continue
		}
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: a.Addr().AsSlice(), Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen())}}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return nil, fmt.Errorf("add address %s: %w", a, hint(err))
		}
	}
	if err := netlink.LinkSetMTU(link, c.MTU); err != nil {
		return nil, fmt.Errorf("set MTU %d: %w", c.MTU, hint(err))
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("set %s up: %w", o.Iface, hint(err))
	}
	routes, err := addRoutes(c, link.Attrs().Index, int(mark), full, v6)
	if err != nil {
		return nil, err
	}
	t.FullTunnel = len(full) > 0
	setDNS(c.DNS)

	addrs := make([]string, len(c.Addresses))
	for i, a := range c.Addresses {
		addrs[i] = a.String()
	}
	Infof("%s up (%s mode): address %s, %d peer(s), MTU %d", o.Iface, t.Mode, strings.Join(addrs, ", "), len(c.Peers), c.MTU)
	for i, p := range c.Peers {
		Infof("  peer %d: endpoint %s, allowed %v", i+1, orNone(p.Endpoint), p.AllowedIPs)
	}
	Infof("  routes: %s", orNone(strings.Join(routes, ", ")))
	return t, nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// create makes the kernel interface, or falls back to wireguard-go.
func (t *Tunnel) create(c *config.Config, o Options) error {
	if o.Mode != "userspace" {
		err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: o.Iface}})
		if errors.Is(err, unix.EEXIST) {
			// Left over in a reused network namespace; it's ours by name, so start fresh.
			Warnf("%s already exists, recreating it", o.Iface)
			if l, lerr := netlink.LinkByName(o.Iface); lerr == nil {
				_ = netlink.LinkDel(l)
			}
			err = netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: o.Iface}})
		}
		if err == nil {
			t.Mode = "kernel"
			return nil
		}
		noModule := errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENODEV)
		if o.Mode == "kernel" || !noModule {
			return fmt.Errorf("create WireGuard interface %s: %w", o.Iface, hint(err))
		}
		Infof("no WireGuard kernel module (%v); falling back to userspace wireguard-go", err)
	}
	d, err := userspace.Start(o.Iface, c.MTU, o.Debug)
	if err != nil {
		return hint(err)
	}
	t.Mode, t.Userspace = "userspace", d
	return nil
}

// hint wraps common errors with what the user should do about them.
func hint(err error) error {
	switch {
	case errors.Is(err, unix.EPERM):
		return fmt.Errorf("%w; add --cap-add NET_ADMIN", err)
	case errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENODEV):
		return fmt.Errorf("%w; the host has no wireguard module: run 'modprobe wireguard' on the host, or use WG_MODE=userspace with --device /dev/net/tun", err)
	case errors.Is(err, unix.EACCES):
		return fmt.Errorf("%w; if this is an IPv6 address, enable IPv6 with --sysctl net.ipv6.conf.default.disable_ipv6=0", err)
	}
	return err
}

func hasV6(c *config.Config) bool {
	for _, a := range c.Addresses {
		if a.Addr().Is6() {
			return true
		}
	}
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if a.Addr().Is6() {
				return true
			}
		}
	}
	return false
}

func ipv6Enabled(iface string) bool {
	b, err := os.ReadFile("/proc/sys/net/ipv6/conf/" + iface + "/disable_ipv6")
	return err == nil && strings.TrimSpace(string(b)) == "0"
}

// routingPlan returns the fwmark to set on the device and the families (by /0) that need
// full-tunnel policy routing.
func routingPlan(c *config.Config, v6 bool) (mark int, full map[int]bool) {
	full = map[int]bool{}
	if c.Table == config.TableAuto {
		for _, p := range c.Peers {
			for _, a := range p.AllowedIPs {
				if a.Bits() == 0 && (a.Addr().Is4() || v6) {
					full[family(a)] = true
				}
			}
		}
	}
	mark = int(c.FwMark)
	if len(full) > 0 && mark == 0 {
		mark = defaultMark
	}
	return mark, full
}

func family(p netip.Prefix) int {
	if p.Addr().Is4() {
		return netlink.FAMILY_V4
	}
	return netlink.FAMILY_V6
}

// deviceConfig builds the wgctrl config, resolving endpoint hostnames.
func deviceConfig(c *config.Config, resolveTimeout time.Duration) (wgtypes.Config, error) {
	key, _ := wgtypes.ParseKey(c.PrivateKey) // validated by the parser
	cfg := wgtypes.Config{PrivateKey: &key, ReplacePeers: true}
	if c.ListenPort != 0 {
		cfg.ListenPort = &c.ListenPort
	}
	for _, p := range c.Peers {
		pc := wgtypes.PeerConfig{ReplaceAllowedIPs: true}
		pc.PublicKey, _ = wgtypes.ParseKey(p.PublicKey)
		if p.PresharedKey != "" {
			k, _ := wgtypes.ParseKey(p.PresharedKey)
			pc.PresharedKey = &k
		}
		if p.Endpoint != "" {
			ep, err := resolve(p.Endpoint, resolveTimeout)
			if err != nil {
				return cfg, err
			}
			pc.Endpoint = ep
		}
		if p.PersistentKeepalive > 0 {
			ka := p.PersistentKeepalive
			pc.PersistentKeepaliveInterval = &ka
		}
		for _, a := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, net.IPNet{IP: a.Addr().AsSlice(), Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen())})
		}
		cfg.Peers = append(cfg.Peers, pc)
	}
	return cfg, nil
}

// resolve retries with backoff because container DNS may not be ready at startup.
func resolve(endpoint string, timeout time.Duration) (*net.UDPAddr, error) {
	deadline := time.Now().Add(timeout)
	wait := 250 * time.Millisecond
	for {
		a, err := net.ResolveUDPAddr("udp", endpoint)
		if err == nil {
			return a, nil
		}
		if time.Now().Add(wait).After(deadline) {
			return nil, fmt.Errorf("resolve Endpoint %s (gave up after %v, raise WG_RESOLVE_TIMEOUT if DNS is slow): %w", endpoint, timeout, err)
		}
		Debugf("resolve %s: %v; retrying in %v", endpoint, err, wait)
		time.Sleep(wait)
		wait = min(wait*2, 5*time.Second)
	}
}

// addRoutes installs routes like wg-quick and returns a human-readable list.
func addRoutes(c *config.Config, idx, mark int, full map[int]bool, v6 bool) ([]string, error) {
	if c.Table == config.TableOff {
		return nil, nil
	}
	var desc []string
	for _, p := range c.Peers {
		for _, a := range p.AllowedIPs {
			if a.Addr().Is6() && !v6 {
				continue
			}
			r := &netlink.Route{LinkIndex: idx, Dst: &net.IPNet{IP: a.Addr().AsSlice(), Mask: net.CIDRMask(a.Bits(), a.Addr().BitLen())}, Scope: netlink.SCOPE_LINK}
			if a.Addr().Is6() {
				r.Scope = netlink.SCOPE_UNIVERSE
			}
			switch {
			case c.Table == config.TableNum:
				r.Table = c.TableID
			case a.Bits() == 0:
				r.Table = mark // default route lives in its own table, see the rules below
			}
			// RouteReplace so a route implied by Address doesn't conflict.
			if err := netlink.RouteReplace(r); err != nil {
				return nil, fmt.Errorf("add route %s: %w", a, hint(err))
			}
			d := a.String()
			if r.Table != 0 {
				d += fmt.Sprintf(" (table %d)", r.Table)
			}
			desc = append(desc, d)
		}
	}

	// Full tunnel, the same policy routing wg-quick uses:
	//   pref 32000: table main suppress_prefixlength 0  (use main for anything more specific than default)
	//   pref 32001: not fwmark M -> table M             (everything else, except WireGuard's own packets)
	//   pref 32002: not fwmark M -> prohibit            (kill switch, see below)
	for fam := range full {
		const svm = "/proc/sys/net/ipv4/conf/all/src_valid_mark"
		if b, _ := os.ReadFile(svm); fam == netlink.FAMILY_V4 && strings.TrimSpace(string(b)) != "1" {
			// /proc/sys is read-only in Docker, so this usually needs --sysctl.
			if err := os.WriteFile(svm, []byte("1"), 0); err != nil {
				Warnf("couldn't set net.ipv4.conf.all.src_valid_mark (%v); run with --sysctl net.ipv4.conf.all.src_valid_mark=1", err)
			}
		}
		suppress := netlink.NewRule()
		suppress.Family, suppress.Table, suppress.SuppressPrefixlen, suppress.Priority = fam, unix.RT_TABLE_MAIN, 0, 32000
		notMark := netlink.NewRule()
		notMark.Family, notMark.Table, notMark.Mark, notMark.Invert, notMark.Priority = fam, mark, uint32(mark), true, 32001
		// Kill switch: unmarked traffic that table M can't route (e.g. a socket bound to eth0 with
		// SO_BINDTODEVICE, or wg0 gone) is refused instead of falling through to main's default route.
		kill := netlink.NewRule()
		kill.Family, kill.Mark, kill.Invert, kill.Priority, kill.Type = fam, uint32(mark), true, 32002, unix.RTN_PROHIBIT
		for _, r := range []*netlink.Rule{suppress, notMark, kill} {
			if err := netlink.RuleAdd(r); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, fmt.Errorf("add ip rule: %w", hint(err))
			}
		}
		desc = append(desc, fmt.Sprintf("full tunnel (IPv%d, fwmark %d)", map[int]int{netlink.FAMILY_V4: 4, netlink.FAMILY_V6: 6}[fam], mark))
	}
	return desc, nil
}

// setDNS writes resolv.conf in place (it's a bind mount in Docker, so no rename).
func setDNS(dns []string) {
	if len(dns) == 0 {
		return
	}
	var ns, search []string
	for _, d := range dns {
		if _, err := netip.ParseAddr(d); err == nil {
			ns = append(ns, "nameserver "+d)
		} else {
			search = append(search, d)
		}
	}
	out := strings.Join(ns, "\n") + "\n"
	if len(search) > 0 {
		out += "search " + strings.Join(search, " ") + "\n"
	}
	if err := os.WriteFile("/etc/resolv.conf", []byte(out), 0o644); err != nil {
		Warnf("couldn't write /etc/resolv.conf for DNS=%s: %v", strings.Join(dns, ","), err)
		return
	}
	Infof("  DNS: %s", strings.Join(dns, ", "))
}

// WaitHandshake blocks until any peer has completed a handshake or timeout passes.
func WaitHandshake(iface string, timeout time.Duration) error {
	wg, err := wgctrl.New()
	if err != nil {
		return err
	}
	defer wg.Close()
	deadline := time.Now().Add(timeout)
	for {
		d, err := wg.Device(iface)
		if err != nil {
			return err
		}
		for i, p := range d.Peers {
			if !p.LastHandshakeTime.IsZero() {
				Infof("handshake with peer %d after %v", i+1, timeout-time.Until(deadline).Round(time.Millisecond))
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no handshake with any peer within %v", timeout)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// loopbackNameserver returns the first 127.x nameserver in resolv.conf (Docker's embedded
// resolver, which forwards from the host's namespace), or "".
func loopbackNameserver(path string) string {
	b, _ := os.ReadFile(path)
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip, err := netip.ParseAddr(f[1]); err == nil && ip.IsLoopback() {
				return f[1]
			}
		}
	}
	return ""
}
