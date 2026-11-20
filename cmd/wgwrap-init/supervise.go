package main

import (
	"time"

	"pkg.bar/wgwrap/internal/config/privdrop"
	"pkg.bar/wgwrap/internal/netsetup"
	"pkg.bar/wgwrap/internal/userspace"
)

func supervise(bin string, args, env []string, cred *privdrop.Cred, t *netsetup.Tunnel) int {
	grace := envDuration("WG_STOP_GRACE", 10*time.Second)
	logAt(2, "", "supervising %s as uid %d", bin, cred.UID)
	return userspace.Supervise(bin, args, env, cred.Syscall(), t.Userspace.Done(), grace,
		func(f string, a ...any) { logAt(0, "", f, a...) })
}
