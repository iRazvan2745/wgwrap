// Package privdrop resolves the image's original USER and switches to it.
//
// User/group lookup mirrors Docker/containerd: it reads the image's /etc/passwd and
// /etc/group (we don't use os/user so tests can point at fixture files), falls back to raw
// numeric ids with gid 0, and always includes the primary gid in the supplementary groups.
package privdrop

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Cred is the identity the app should run as.
type Cred struct {
	UID, GID uint32
	Groups   []uint32
	Home     string
}

// IsRoot reports whether no switch is needed.
func (c *Cred) IsRoot() bool { return c.UID == 0 && c.GID == 0 }

// Syscall converts to the form used by os.StartProcess.
func (c *Cred) Syscall() *syscall.Credential {
	return &syscall.Credential{Uid: c.UID, Gid: c.GID, Groups: c.Groups}
}

// readColon returns the colon-separated records of a passwd/group style file.
func readColon(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		out = append(out, strings.Split(line, ":"))
	}
	return out, sc.Err()
}

func parseID(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

// Resolve turns a Docker USER spec (name, uid, name:group, uid:gid) into a Cred, using
// root+"/etc/passwd" and root+"/etc/group". Empty spec means root.
func Resolve(spec, root string) (*Cred, error) {
	if spec == "" || spec == "root" {
		spec = "0" // stay root; works without a passwd file
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	passwd, _ := readColon(filepath.Join(root, "etc/passwd")) // missing file is normal (distroless, scratch)
	groups, _ := readColon(filepath.Join(root, "etc/group"))

	c := &Cred{Home: "/"}
	name := ""
	found := false
	uid, numeric := parseID(userPart)
	for _, p := range passwd {
		if len(p) < 7 {
			continue
		}
		if (numeric && p[2] == userPart) || (!numeric && p[0] == userPart) {
			u, ok1 := parseID(p[2])
			g, ok2 := parseID(p[3])
			if !ok1 || !ok2 {
				return nil, fmt.Errorf("user %q: malformed /etc/passwd entry", userPart)
			}
			c.UID, c.GID, c.Home, name, found = u, g, p[5], p[0], true
			break
		}
	}
	if !found {
		if !numeric {
			return nil, fmt.Errorf("user %q not found in the image's /etc/passwd", userPart)
		}
		c.UID = uid // Docker semantics: unknown numeric uid gets gid 0
	}

	if hasGroup {
		g, ok := parseID(groupPart)
		if !ok {
			for _, gr := range groups {
				if len(gr) >= 3 && gr[0] == groupPart {
					g, ok = parseID(gr[2])
					break
				}
			}
			if !ok {
				return nil, fmt.Errorf("group %q not found in the image's /etc/group", groupPart)
			}
		}
		c.GID = g
	}

	c.Groups = []uint32{c.GID}
	if name != "" {
		for _, gr := range groups {
			if len(gr) < 4 || !slices.Contains(strings.Split(gr[3], ","), name) {
				continue
			}
			if g, ok := parseID(gr[2]); ok && !slices.Contains(c.Groups, g) {
				c.Groups = append(c.Groups, g)
			}
		}
	}
	return c, nil
}

// Apply switches this process to c: supplementary groups, gid, uid, in that order.
// Go's syscall versions apply to all OS threads.
func Apply(c *Cred) error {
	gs := make([]int, len(c.Groups))
	for i, g := range c.Groups {
		gs[i] = int(g)
	}
	if err := syscall.Setgroups(gs); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(int(c.GID)); err != nil {
		return fmt.Errorf("setgid %d: %w", c.GID, err)
	}
	if err := syscall.Setuid(int(c.UID)); err != nil {
		return fmt.Errorf("setuid %d: %w", c.UID, err)
	}
	return nil
}

// DropCap removes capability cap from the bounding and inheritable sets of every thread.
// On execve the new permitted set of a root process is inheritable|bounding, so this is what
// keeps the app (even if it stays root) from regaining the capability. A non-root app loses
// all capabilities at setuid anyway. The effective/permitted sets are left alone so the
// supervisor in userspace mode can keep running wireguard-go.
func DropCap(cap uintptr) error {
	if r, _ := unix.PrctlRetInt(unix.PR_CAPBSET_READ, cap, 0, 0, 0); r == 0 {
		return nil // never held (e.g. --cap-drop ALL), nothing the app could use
	}
	// Requires CGO_ENABLED=0 (AllThreadsSyscall refuses to run with cgo).
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAPBSET_DROP, cap, 0); e != 0 {
		return fmt.Errorf("drop from bounding set: %w (missing CAP_SETPCAP?)", e)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	data[cap/32].Inheritable &^= 1 << (cap % 32)
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("capset: %w", e)
	}
	return nil
}

// FixStdio hands stdin/stdout/stderr to uid, like runc does for a non-root USER. Without it the
// app can't reopen /dev/stdout or /dev/stderr (nginx logs to symlinks to them), because Docker
// created them for root, which is who wgwrap starts as.
func FixStdio(uid uint32) {
	var null unix.Stat_t
	_ = unix.Stat("/dev/null", &null)
	for fd := 0; fd <= 2; fd++ {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Uid == uid || (st.Mode&unix.S_IFMT == unix.S_IFCHR && st.Rdev == null.Rdev) {
			continue
		}
		_ = unix.Fchown(fd, int(uid), -1) // best effort, as in runc
	}
}

// CanRead reports whether c could read path, judged by its mode bits.
// shortcut: ignores ACLs and parent directory permissions (errs towards "readable"), fine for a mounted config file.
func CanRead(path string, c *Cred) bool {
	var st unix.Stat_t
	if unix.Stat(path, &st) != nil {
		return false
	}
	switch {
	case c.UID == 0:
		return true
	case st.Uid == c.UID:
		return st.Mode&0o400 != 0
	case st.Gid == c.GID || slices.Contains(c.Groups, st.Gid):
		return st.Mode&0o040 != 0
	}
	return st.Mode&0o004 != 0
}
