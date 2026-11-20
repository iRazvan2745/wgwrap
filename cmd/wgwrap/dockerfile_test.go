package main

import (
	"strings"
	"testing"
)

func TestGenerateDockerfile(t *testing.T) {
	cases := []struct {
		name string
		spec buildSpec
		want []string // lines that must appear
		not  []string // substrings that must not
	}{
		{
			name: "entrypoint+cmd",
			spec: buildSpec{Orig: imageConfig{Entrypoint: []string{"/docker-entrypoint.sh"}, Cmd: []string{"nginx", "-g", "daemon off;"}}},
			want: []string{
				`ENTRYPOINT ["/wgwrap-init","--","/docker-entrypoint.sh"]`,
				`CMD ["nginx","-g","daemon off;"]`,
				`ENV WGWRAP_USER=""`,
			},
		},
		{
			name: "cmd only",
			spec: buildSpec{Orig: imageConfig{Cmd: []string{"/bin/sh"}}},
			want: []string{`ENTRYPOINT ["/wgwrap-init","--"]`, `CMD ["/bin/sh"]`},
		},
		{
			name: "entrypoint only",
			spec: buildSpec{Orig: imageConfig{Entrypoint: []string{"/app"}}},
			want: []string{`ENTRYPOINT ["/wgwrap-init","--","/app"]`},
			not:  []string{"CMD"},
		},
		{
			name: "neither",
			spec: buildSpec{},
			want: []string{`ENTRYPOINT ["/wgwrap-init","--"]`},
			not:  []string{"CMD"},
		},
		{
			name: "user with group",
			spec: buildSpec{Orig: imageConfig{User: "nginx:nginx", Cmd: []string{"x"}}},
			want: []string{`ENV WGWRAP_USER="nginx:nginx"`, "USER root"},
		},
		{
			name: "numeric user",
			spec: buildSpec{Orig: imageConfig{User: "65532", Cmd: []string{"x"}}},
			want: []string{`ENV WGWRAP_USER="65532"`},
		},
		{
			name: "quotes, spaces, unicode, html",
			spec: buildSpec{Orig: imageConfig{Cmd: []string{"sh", "-c", `echo "hi there" <ü> & \ done`}}},
			want: []string{`CMD ["sh","-c","echo \"hi there\" <ü> & \\ done"]`},
		},
		{
			name: "bake + optional",
			spec: buildSpec{BakeConf: true, Optional: true, Orig: imageConfig{Cmd: []string{"x"}}},
			want: []string{"COPY --chmod=0600 wg0.conf /etc/wireguard/wg0.conf", "ENV WG_OPTIONAL=1"},
		},
	}
	for _, c := range cases {
		c.spec.Source, c.spec.Origin, c.spec.InitImage, c.spec.Version = "src:1", "src:1", "init:v1", "v1"
		df := generateDockerfile(c.spec)
		lines := strings.Split(df, "\n")
		for _, w := range append(c.want, "FROM init:v1 AS wgwrap", "FROM src:1", "COPY --from=wgwrap /wgwrap-init /wgwrap-init",
			`LABEL io.wgwrap.source="src:1" io.wgwrap.version="v1"`) {
			found := false
			for _, l := range lines {
				found = found || l == w
			}
			if !found {
				t.Errorf("%s: missing line %q in:\n%s", c.name, w, df)
			}
		}
		for _, n := range c.not {
			if strings.Contains(df, n) {
				t.Errorf("%s: unexpected %q in:\n%s", c.name, n, df)
			}
		}
	}
}

func TestOriginalUnwrapsOnce(t *testing.T) {
	wrapped := imageConfig{
		Entrypoint: []string{"/wgwrap-init", "--", "/docker-entrypoint.sh"},
		Cmd:        []string{"nginx"},
		User:       "root",
		Env:        []string{"PATH=/bin", `WGWRAP_USER=101:101`},
		Labels:     map[string]string{labelSource: "nginx:latest"},
	}
	o, src := wrapped.original("nginx-wg")
	if src != "nginx:latest" || o.User != "101:101" || jsonArray(o.Entrypoint) != `["/docker-entrypoint.sh"]` || o.Cmd[0] != "nginx" {
		t.Errorf("got %+v from %s", o, src)
	}
	plain := imageConfig{Entrypoint: []string{"/x"}, User: "app"}
	if o, src := plain.original("app:1"); src != "app:1" || o.User != "app" {
		t.Errorf("unwrapped image changed: %+v %s", o, src)
	}
}

func TestParseImagetools(t *testing.T) {
	single := `{"config":{"Entrypoint":["/e"],"Cmd":["c"],"User":"u"}}`
	if c, err := parseImagetools([]byte(single), ""); err != nil || c.User != "u" {
		t.Errorf("single: %+v %v", c, err)
	}
	multi := `{"linux/amd64":{"config":{"Cmd":["c"]}},"linux/arm64":{"config":{"Cmd":["c"]}}}`
	if c, err := parseImagetools([]byte(multi), ""); err != nil || c.Cmd[0] != "c" {
		t.Errorf("multi: %+v %v", c, err)
	}
	differ := `{"linux/amd64":{"config":{"Cmd":["a"]}},"linux/arm64":{"config":{"Cmd":["b"]}}}`
	if _, err := parseImagetools([]byte(differ), ""); err == nil || !strings.Contains(err.Error(), "different") {
		t.Errorf("differ: %v", err)
	}
	if c, err := parseImagetools([]byte(differ), "linux/arm64"); err != nil || c.Cmd[0] != "b" {
		t.Errorf("differ, filtered: %+v %v", c, err)
	}
	win := `{"linux/amd64":{"config":{"Cmd":["python3"]}},"windows/amd64":{"config":{"Cmd":["cmd"]}}}`
	if c, err := parseImagetools([]byte(win), ""); err != nil || c.Cmd[0] != "python3" {
		t.Errorf("windows variant should be ignored: %+v %v", c, err)
	}
	if _, err := parseImagetools([]byte(multi), "linux/s390x"); err == nil {
		t.Errorf("missing platform should fail")
	}
}
