package privdrop

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	cases := []struct {
		spec, root string
		want       Cred
	}{
		{"", "testdata", Cred{0, 0, []uint32{0}, "/root"}},
		{"root", "testdata", Cred{0, 0, []uint32{0}, "/root"}},
		{"nginx", "testdata", Cred{101, 101, []uint32{101}, "/var/cache/nginx"}},
		{"101", "testdata", Cred{101, 101, []uint32{101}, "/var/cache/nginx"}},
		{"app", "testdata", Cred{1000, 1000, []uint32{1000, 29, 44}, "/home/app"}},
		{"app:staff", "testdata", Cred{1000, 50, []uint32{50, 29, 44}, "/home/app"}},
		{"app:7", "testdata", Cred{1000, 7, []uint32{7, 29, 44}, "/home/app"}},
		{"1234", "testdata", Cred{1234, 0, []uint32{0}, "/"}},
		{"1234:1234", "testdata", Cred{1234, 1234, []uint32{1234}, "/"}},
		// No passwd/group at all (distroless/scratch): numeric ids work as-is.
		{"65532", "testdata-empty", Cred{65532, 0, []uint32{0}, "/"}},
		{"65532:65532", "testdata-empty", Cred{65532, 65532, []uint32{65532}, "/"}},
		{"", "testdata-empty", Cred{0, 0, []uint32{0}, "/"}},
	}
	for _, c := range cases {
		got, err := Resolve(c.spec, c.root)
		if err != nil {
			t.Errorf("Resolve(%q, %s): %v", c.spec, c.root, err)
			continue
		}
		if !reflect.DeepEqual(*got, c.want) {
			t.Errorf("Resolve(%q, %s) = %+v, want %+v", c.spec, c.root, *got, c.want)
		}
	}
}

func TestResolveErrors(t *testing.T) {
	for spec, want := range map[string]string{
		"nobody":     `user "nobody" not found`,
		"app:nogrp":  `group "nogrp" not found`,
		"broken":     "malformed",
		"ghost:1000": `user "ghost" not found`,
	} {
		if _, err := Resolve(spec, "testdata"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Resolve(%q) err = %v, want %q", spec, err, want)
		}
	}
}
