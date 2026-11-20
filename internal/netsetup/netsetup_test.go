package netsetup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoopbackNameserver(t *testing.T) {
	dir := t.TempDir()
	for content, want := range map[string]string{
		"nameserver 127.0.0.11\noptions ndots:0\n": "127.0.0.11", // Docker user-defined network
		"search x\nnameserver 8.8.8.8\n":           "",           // default bridge: goes through the tunnel
		"nameserver ::1\n":                         "::1",
		"":                                         "",
	} {
		p := filepath.Join(dir, "resolv.conf")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := loopbackNameserver(p); got != want {
			t.Errorf("%q: got %q, want %q", content, got, want)
		}
	}
}
