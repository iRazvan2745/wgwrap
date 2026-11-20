package userspace

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// forwarded are the catchable signals passed through to the app.
var forwarded = []os.Signal{unix.SIGTERM, unix.SIGINT, unix.SIGHUP, unix.SIGQUIT, unix.SIGUSR1, unix.SIGUSR2, unix.SIGWINCH}

// ExitCode maps a wait status to a shell-style exit code (128+signal when killed).
func ExitCode(ws unix.WaitStatus) int {
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ws.ExitStatus()
}

// Supervise runs the app as a child of this process (which is PID 1), forwards signals,
// reaps orphaned zombies and returns the app's exit code. If devDone closes first, the app
// is sent SIGTERM, then SIGKILL after grace, and a non-zero code is returned.
func Supervise(path string, argv, env []string, cred *syscall.Credential, devDone <-chan struct{}, grace time.Duration, logf func(string, ...any)) int {
	sigs := make(chan os.Signal, 32)
	signal.Notify(sigs, append([]os.Signal{unix.SIGCHLD}, forwarded...)...)
	defer signal.Stop(sigs)

	// No Setsid/Setpgid: the app stays in our session and process group so the TTY of
	// `docker run -it` keeps working.
	// shortcut: with -t, Ctrl-C reaches the app from both the kernel and our forwarding; move the app to its own foreground pgrp if that bites.
	p, err := os.StartProcess(path, argv, &os.ProcAttr{
		Env:   env,
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		Sys:   &syscall.SysProcAttr{Credential: cred},
	})
	if err != nil {
		logf("start %s: %v", path, err)
		return 127
	}
	pid := p.Pid

	var killTimer <-chan time.Time
	tunnelDied := false
	for {
		select {
		case s := <-sigs:
			if s != unix.SIGCHLD {
				_ = unix.Kill(pid, s.(unix.Signal))
				continue
			}
			// We're PID 1: reap everything, not just our direct child.
			for {
				var ws unix.WaitStatus
				wpid, err := unix.Wait4(-1, &ws, unix.WNOHANG, nil)
				if wpid <= 0 || err != nil {
					break
				}
				if wpid == pid {
					if tunnelDied {
						return 1
					}
					return ExitCode(ws)
				}
			}
		case <-devDone:
			devDone = nil
			tunnelDied = true
			logf("WireGuard device stopped; sending SIGTERM to the app")
			_ = unix.Kill(pid, unix.SIGTERM)
			killTimer = time.After(grace)
		case <-killTimer:
			logf("app still running after %v; sending SIGKILL", grace)
			_ = unix.Kill(pid, unix.SIGKILL)
		}
	}
}
