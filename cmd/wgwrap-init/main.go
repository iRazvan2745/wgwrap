// wgwrap-init is the entrypoint of wrapped images: it brings up WireGuard in the container's
// network namespace, drops privileges and hands off to the original entrypoint.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"pkg.bar/wgwrap/internal/config"
	"pkg.bar/wgwrap/internal/config/privdrop"
	"pkg.bar/wgwrap/internal/netsetup"
)

var version = "dev"

var logLevel = 1 // 0 quiet, 1 info, 2 debug

func logAt(min int, prefix, f string, a ...any) {
	if logLevel >= min {
		fmt.Fprintf(os.Stderr, "wgwrap: "+prefix+f+"\n", a...)
	}
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "wgwrap: error: "+f+"\n", a...)
	os.Exit(1)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		die("%s=%q is not a duration (e.g. 30s)", k, v)
	}
	return d
}

// loadConfig returns nil, nil when there is no config at all.
func loadConfig() (*config.Config, string, error) {
	if b64 := os.Getenv("WG_CONFIG_B64"); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
		if err != nil {
			return nil, "WG_CONFIG_B64", fmt.Errorf("not valid base64: %w", err)
		}
		c, err := config.Parse(bytes.NewReader(raw))
		return c, "WG_CONFIG_B64", err
	}
	path := envOr("WG_CONFIG", "/etc/wireguard/wg0.conf")
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, path, nil
	}
	if err != nil {
		return nil, path, err
	}
	defer f.Close()
	c, err := config.Parse(f)
	return c, path, err
}

// appEnv is our environment minus the secret config, with HOME fixed up for the target user.
func appEnv(cred *privdrop.Cred) []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "WG_CONFIG_B64="):
			continue
		// Docker sets HOME=/root because we start as root; the original image would have
		// started with the target user's home.
		// shortcut: an explicit `-e HOME=/root` for a non-root user is also replaced.
		case kv == "HOME=/root" && cred.UID != 0:
			kv = "HOME=" + cred.Home
		}
		env = append(env, kv)
	}
	return env
}

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println("wgwrap-init", version)
		return
	}
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	switch envOr("WG_LOG", "info") {
	case "quiet":
		logLevel = 0
	case "debug":
		logLevel = 2
	}
	netsetup.Infof = func(f string, a ...any) { logAt(1, "", f, a...) }
	netsetup.Warnf = func(f string, a ...any) { logAt(0, "warning: ", f, a...) }
	netsetup.Debugf = func(f string, a ...any) { logAt(2, "", f, a...) }

	if len(args) == 0 {
		die("no command to run: the image has neither ENTRYPOINT nor CMD; pass one to docker run")
	}
	if os.Geteuid() != 0 {
		die("wgwrap-init must start as root to configure WireGuard, but runs as uid %d.\n"+
			"Don't use --user (or compose 'user:'); pass the user as -e WGWRAP_USER=%d instead, and wgwrap switches to it after setup.", os.Geteuid(), os.Geteuid())
	}

	cfg, src, err := loadConfig()
	if err != nil {
		die("config %s: %v", src, err)
	}
	var tunnel *netsetup.Tunnel
	switch {
	case cfg == nil && os.Getenv("WG_OPTIONAL") == "1":
		logAt(1, "", "no config at %s and WG_OPTIONAL=1: starting without WireGuard", src)
	case cfg == nil:
		die("no WireGuard config: mount one at %s (-v ./wg0.conf:%s:ro), set WG_CONFIG or WG_CONFIG_B64, or set WG_OPTIONAL=1 to run without a tunnel", src, src)
	default:
		for _, w := range cfg.Warnings {
			logAt(0, "warning: ", "%s: %s", src, w)
		}
		mode := envOr("WG_MODE", "auto")
		if mode != "auto" && mode != "kernel" && mode != "userspace" {
			die("WG_MODE=%q: want auto, kernel or userspace", mode)
		}
		tunnel, err = netsetup.Up(cfg, netsetup.Options{
			Iface:          envOr("WG_INTERFACE", "wg0"),
			Mode:           mode,
			ResolveTimeout: envDuration("WG_RESOLVE_TIMEOUT", 30*time.Second),
			Debug:          logLevel == 2,
		})
		if err != nil {
			die("%v", err)
		}
		if d := envDuration("WG_WAIT_HANDSHAKE", 0); d > 0 {
			if err := netsetup.WaitHandshake(tunnel.Iface, d); err != nil {
				if os.Getenv("WG_WAIT_HANDSHAKE_STRICT") == "1" {
					die("%v", err)
				}
				logAt(0, "warning: ", "%v; starting anyway", err)
			}
		}
		if tunnel.Userspace != nil {
			tunnel.Userspace.CloseUAPI()
		}
	}

	cred, err := privdrop.Resolve(os.Getenv("WGWRAP_USER"), "/")
	if err != nil {
		die("WGWRAP_USER=%q: %v", os.Getenv("WGWRAP_USER"), err)
	}
	if os.Getenv("WG_DROP_CAPS") != "0" {
		// NET_RAW is left alone: wgwrap never gains it, so it is exactly as the user configured.
		if err := privdrop.DropCap(unix.CAP_NET_ADMIN); err != nil {
			logAt(0, "warning: ", "couldn't drop CAP_NET_ADMIN, the app could reconfigure the tunnel: %v", err)
		}
	}
	if !cred.IsRoot() {
		privdrop.FixStdio(cred.UID)
	}
	env := appEnv(cred)
	bin, err := exec.LookPath(args[0]) // uses the image's own PATH, which we inherited
	if err != nil {
		die("%v", err)
	}

	if tunnel != nil && tunnel.Userspace != nil {
		// The tunnel lives in this process, so stay alive as a minimal init.
		os.Exit(supervise(bin, args, env, cred, tunnel))
	}
	if !cred.IsRoot() {
		if err := privdrop.Apply(cred); err != nil {
			die("switch to WGWRAP_USER=%q: %v", os.Getenv("WGWRAP_USER"), err)
		}
	}
	logAt(2, "", "exec %s as uid %d", bin, cred.UID)
	if err := syscall.Exec(bin, args, env); err != nil {
		die("exec %s: %v", bin, err)
	}
}
