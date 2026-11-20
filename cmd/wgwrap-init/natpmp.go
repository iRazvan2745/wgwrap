package main

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"pkg.bar/wgwrap/internal/natpmp"
)

const (
	natpmpLifetime = 60 * time.Second
	natpmpRenew    = 45 * time.Second
	natpmpRetry    = 5 * time.Second
	hookTimeout    = 30 * time.Second
)

// children lets goroutines wait for processes they started while the supervisor, as PID 1,
// does all the reaping.
type children struct {
	mu      sync.Mutex
	waiting map[int]chan unix.WaitStatus
}

func (c *children) start(argv, env []string, cred *syscall.Credential) (int, <-chan unix.WaitStatus, error) {
	// Held across StartProcess so reaped can't see the pid before it is registered.
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := os.StartProcess(argv[0], argv, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{nil, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{Credential: cred},
	})
	if err != nil {
		return 0, nil, err
	}
	ch := make(chan unix.WaitStatus, 1)
	c.waiting[p.Pid] = ch
	return p.Pid, ch, nil
}

func (c *children) reaped(pid int, ws unix.WaitStatus) {
	c.mu.Lock()
	ch := c.waiting[pid]
	delete(c.waiting, pid)
	c.mu.Unlock()
	if ch != nil {
		ch <- ws
	}
}

// runHook runs WG_NATPMP_CMD through /bin/sh as the app user, with the port in WG_NATPMP_PORT.
func (c *children) runHook(hook string, port uint16, env []string, cred *syscall.Credential) error {
	env = append(env[:len(env):len(env)], fmt.Sprintf("WG_NATPMP_PORT=%d", port))
	pid, done, err := c.start([]string{"/bin/sh", "-c", hook}, env, cred)
	if err != nil {
		return err
	}
	var ws unix.WaitStatus
	select {
	case ws = <-done:
	case <-time.After(hookTimeout):
		_ = unix.Kill(pid, unix.SIGKILL)
		<-done
		return fmt.Errorf("killed after %v", hookTimeout)
	}
	if code := ws.ExitStatus(); ws.Signaled() || code != 0 {
		return fmt.Errorf("exit status %d", code)
	}
	return nil
}

// natpmpLoop keeps a UDP and a TCP mapping alive on gw and runs the hook whenever the public
// port changes, retrying sooner after a failure. It never returns.
func natpmpLoop(gw netip.Addr, hook string, kids *children, env []string, cred *syscall.Credential) {
	ap := netip.AddrPortFrom(gw, natpmp.Port)
	var applied uint16
	for {
		wait := natpmpRenew
		udp, err := natpmp.Map(ap, false, natpmpLifetime)
		var tcp uint16
		if err == nil {
			tcp, err = natpmp.Map(ap, true, natpmpLifetime)
		}
		switch {
		case err != nil:
			logAt(0, "warning: ", "NAT-PMP: %v; retrying in %v", err, natpmpRetry)
			wait = natpmpRetry
		case tcp == applied:
			logAt(2, "", "NAT-PMP: renewed port %d", tcp)
		default:
			if udp != tcp {
				logAt(0, "warning: ", "NAT-PMP: gateway mapped UDP %d but TCP %d; using TCP", udp, tcp)
			}
			logAt(1, "", "NAT-PMP: public port %d via %s", tcp, gw)
			if hook == "" {
				applied = tcp
			} else if err := kids.runHook(hook, tcp, env, cred); err != nil {
				logAt(0, "warning: ", "WG_NATPMP_CMD for port %d: %v; retrying in %v", tcp, err, natpmpRetry)
				wait = natpmpRetry
			} else {
				applied = tcp
			}
		}
		time.Sleep(wait)
	}
}
