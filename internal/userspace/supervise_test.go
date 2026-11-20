package userspace

import (
	"os"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestExitCode(t *testing.T) {
	cases := []struct {
		ws   unix.WaitStatus
		want int
	}{
		{0, 0},
		{3 << 8, 3},
		{255 << 8, 255},
		{unix.WaitStatus(unix.SIGTERM), 143},
		{unix.WaitStatus(unix.SIGKILL), 137},
		{unix.WaitStatus(unix.SIGSEGV) | 0x80, 139}, // core dumped
	}
	for _, c := range cases {
		if got := ExitCode(c.ws); got != c.want {
			t.Errorf("ExitCode(%#x) = %d, want %d", uint32(c.ws), got, c.want)
		}
	}
}

func TestSuperviseExitAndSignal(t *testing.T) {
	sh := "/bin/sh"
	if _, err := os.Stat(sh); err != nil {
		t.Skip("no /bin/sh")
	}
	logf := func(f string, a ...any) { t.Logf(f, a...) }
	if got := Supervise(sh, []string{"sh", "-c", "exit 7"}, nil, nil, nil, time.Second, logf, nil); got != 7 {
		t.Errorf("exit 7: got %d", got)
	}

	// Forwarded SIGUSR1 must reach the child, which exits with a code from its trap.
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = syscall.Kill(os.Getpid(), syscall.SIGUSR1)
	}()
	if got := Supervise(sh, []string{"sh", "-c", `trap "exit 42" USR1; i=0; while [ $i -lt 50 ]; do sleep 0.1; i=$((i+1)); done; exit 1`}, nil, nil, nil, time.Second, logf, nil); got != 42 {
		t.Errorf("signal forward: got %d", got)
	}

	// Device death: TERM, then KILL after grace, non-zero result.
	done := make(chan struct{})
	close(done)
	if got := Supervise(sh, []string{"sh", "-c", `trap "" TERM; sleep 5`}, nil, nil, done, 200*time.Millisecond, logf, nil); got != 1 {
		t.Errorf("device death: got %d", got)
	}
}

// Other children are reported to reaped, including one that exited before Supervise started.
func TestSuperviseReportsOtherChildren(t *testing.T) {
	sh := "/bin/sh"
	if _, err := os.Stat(sh); err != nil {
		t.Skip("no /bin/sh")
	}
	early, err := os.StartProcess(sh, []string{"sh", "-c", "exit 3"}, &os.ProcAttr{})
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let it exit before Supervise listens for SIGCHLD
	got := map[int]int{}
	reaped := func(pid int, ws unix.WaitStatus) { got[pid] = ExitCode(ws) }
	logf := func(f string, a ...any) { t.Logf(f, a...) }
	if code := Supervise(sh, []string{"sh", "-c", "sleep 0.2"}, nil, nil, nil, time.Second, logf, reaped); code != 0 {
		t.Errorf("app exit: got %d", code)
	}
	if code, ok := got[early.Pid]; !ok || code != 3 {
		t.Errorf("early child: reaped=%v, want pid %d with code 3", got, early.Pid)
	}
}
