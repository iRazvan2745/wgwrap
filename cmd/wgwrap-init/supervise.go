package main

import (
	"time"

	"golang.org/x/sys/unix"

	"pkg.bar/wgwrap/internal/config/privdrop"
	"pkg.bar/wgwrap/internal/netsetup"
	"pkg.bar/wgwrap/internal/userspace"
)

func supervise(bin string, args, env []string, cred *privdrop.Cred, t *netsetup.Tunnel, reaped func(int, unix.WaitStatus)) int {
	grace := envDuration("WG_STOP_GRACE", 10*time.Second)
	var devDone <-chan struct{} // nil in kernel mode: the kernel keeps wg0 alive
	if t.Userspace != nil {
		devDone = t.Userspace.Done()
	}
	logAt(2, "", "supervising %s as uid %d", bin, cred.UID)
	return userspace.Supervise(bin, args, env, cred.Syscall(), devDone, grace,
		func(f string, a ...any) { logAt(0, "", f, a...) }, reaped)
}
