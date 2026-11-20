package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"pkg.bar/wgwrap/internal/userspace"
)

// The hook's exit status must reach runHook even though Supervise does all the reaping.
func TestRunHookUnderSupervise(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	kids := &children{waiting: map[int]chan unix.WaitStatus{}}
	out := t.TempDir() + "/port"
	errs := make(chan error, 2)
	go func() {
		errs <- kids.runHook(`echo "$WG_NATPMP_PORT" > "$OUT"`, 51234, []string{"OUT=" + out}, nil)
		errs <- kids.runHook("exit 4", 1, nil, nil)
	}()
	logf := func(f string, a ...any) { t.Logf(f, a...) }
	if code := userspace.Supervise("/bin/sh", []string{"sh", "-c", "sleep 1"}, nil, nil, nil, time.Second, logf, kids.reaped); code != 0 {
		t.Fatalf("app exit: got %d", code)
	}

	if err := <-errs; err != nil {
		t.Errorf("hook: %v", err)
	}
	if b, _ := os.ReadFile(out); strings.TrimSpace(string(b)) != "51234" {
		t.Errorf("hook saw WG_NATPMP_PORT=%q, want 51234", b)
	}
	if err := <-errs; err == nil || !strings.Contains(err.Error(), "exit status 4") {
		t.Errorf("failing hook: got %v", err)
	}
}
