// wgwrap wraps any Docker image so it brings up its own WireGuard interface at startup.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

var (
	version          = "dev"
	defaultInitImage = "localhost/wgwrap-init" // "localhost/" never resolves to Docker Hub; set the real one via -ldflags
)

const usage = `usage:
  wgwrap build <source-image> -t <tag> [--platform linux/amd64,linux/arm64] [--push]
               [--init-image IMAGE] [--config wg0.conf] [--optional] [--dry-run]
  wgwrap inspect <image>
  wgwrap version
`

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "wgwrap: "+f+"\n", a...)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "build":
		err = build(os.Args[2:])
	case "inspect":
		err = inspectCmd(os.Args[2:])
	case "version", "--version":
		fmt.Println("wgwrap", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		die("%v", err)
	}
}

// parseInterleaved lets flags appear before or after the positional args.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func build(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	tag := fs.String("t", "", "tag for the wrapped image (required)")
	platform := fs.String("platform", "", "comma-separated target platforms")
	push := fs.Bool("push", false, "push the result instead of loading it locally")
	initImage := fs.String("init-image", defaultInitImage+":"+version, "image that provides /wgwrap-init")
	confPath := fs.String("config", "", "bake this wg-quick config into the image (contains a private key!)")
	optional := fs.Bool("optional", false, "start without a tunnel if no config is present (sets WG_OPTIONAL=1)")
	dryRun := fs.Bool("dry-run", false, "print the generated Dockerfile and exit")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || (*tag == "" && !*dryRun) {
		return errors.New("usage: wgwrap build <source-image> -t <tag> [flags]")
	}
	source := pos[0]

	cfg, err := imageConfigOf(source, *platform)
	if err != nil {
		return err
	}
	orig, origin := cfg.original(source)
	if origin != source {
		fmt.Fprintf(os.Stderr, "wgwrap: %s is already wrapped (from %s); re-wrapping the original entrypoint\n", source, origin)
	}
	if len(orig.Entrypoint) == 0 && len(orig.Cmd) == 0 {
		fmt.Fprintf(os.Stderr, "wgwrap: warning: %s has no ENTRYPOINT or CMD; pass a command to docker run\n", source)
	}
	spec := buildSpec{Source: source, Origin: origin, InitImage: *initImage, Version: version, Orig: orig, BakeConf: *confPath != "", Optional: *optional}
	df := generateDockerfile(spec)
	if *dryRun {
		fmt.Print(df)
		return nil
	}

	dir, err := os.MkdirTemp("", "wgwrap-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(df), 0o644); err != nil {
		return err
	}
	if *confPath != "" {
		conf, err := os.ReadFile(*confPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "wg0.conf"), conf, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "\nwgwrap: WARNING: %s is baked into %s, INCLUDING ITS PRIVATE KEY.\n"+
			"wgwrap: Anyone who can pull this image can impersonate this peer. Don't push it to a shared registry.\n\n", *confPath, *tag)
	}

	cmd := []string{"buildx", "build", "-t", *tag}
	if *platform != "" {
		cmd = append(cmd, "--platform", *platform)
	}
	if *push {
		cmd = append(cmd, "--push")
	} else {
		cmd = append(cmd, "--load")
	}
	cmd = append(cmd, dir)
	c := exec.Command("docker", cmd...)
	c.Stdout, c.Stderr = os.Stderr, os.Stderr
	if err := c.Run(); err != nil {
		return fmt.Errorf("docker %s: %w", strings.Join(cmd, " "), err)
	}
	fmt.Fprintf(os.Stderr, "wgwrap: built %s\nwgwrap: run it with: docker run --cap-add NET_ADMIN -v ./wg0.conf:/etc/wireguard/wg0.conf:ro %s\n", *tag, *tag)
	return nil
}

func inspectCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: wgwrap inspect <image>")
	}
	cfg, err := imageConfigOf(args[0], "")
	if err != nil {
		return err
	}
	orig, origin := cfg.original(args[0])
	show := func(title string, c imageConfig) {
		fmt.Printf("%s\n  Entrypoint: %s\n  Cmd:        %s\n  User:       %s\n", title, jsonArray(c.Entrypoint), jsonArray(c.Cmd), jsonString(c.User))
	}
	if origin == args[0] {
		show("original ("+origin+"), not wrapped:", orig)
		w := orig
		w.Entrypoint = append([]string{initPath, "--"}, orig.Entrypoint...)
		w.User = "root (switches to " + jsonString(orig.User) + " after setup)"
		show("after wgwrap build:", w)
		return nil
	}
	show("original ("+origin+"):", orig)
	cfg.User += " (switches to " + jsonString(orig.User) + " after setup)"
	show(fmt.Sprintf("wrapped (wgwrap %s):", cfg.Labels[labelVersion]), cfg)
	return nil
}

// imageConfigOf reads an image's config without pulling it, falling back to the local store.
// stderrOf includes the command's stderr in its error.
func stderrOf(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) && len(ee.Stderr) > 0 {
		return errors.New(strings.TrimSpace(string(ee.Stderr)))
	}
	return err
}

func imageConfigOf(image, platforms string) (imageConfig, error) {
	out, err := exec.Command("docker", "buildx", "imagetools", "inspect", image, "--format", "{{json .Image}}").Output()
	if err == nil {
		return parseImagetools(out, platforms)
	}
	// Any failure (local-only image, no registry access): try the local image store.
	out, lerr := exec.Command("docker", "image", "inspect", "--format", "{{json .Config}}", image).Output()
	if lerr != nil {
		return imageConfig{}, fmt.Errorf("can't read the config of %s: registry lookup failed (%v) and not found locally (%v)", image, stderrOf(err), stderrOf(lerr))
	}
	var c imageConfig
	return c, json.Unmarshal(out, &c)
}

// parseImagetools handles both shapes `imagetools inspect` prints: a single image config,
// or a map of platform -> config for multi-arch images.
func parseImagetools(out []byte, only string) (imageConfig, error) {
	var single struct {
		Config *imageConfig `json:"config"`
	}
	if err := json.Unmarshal(out, &single); err == nil && single.Config != nil {
		return *single.Config, nil
	}
	var multi map[string]struct {
		Config imageConfig `json:"config"`
	}
	if err := json.Unmarshal(out, &multi); err != nil {
		return imageConfig{}, fmt.Errorf("unexpected imagetools output: %w", err)
	}
	if len(multi) == 0 {
		return imageConfig{}, errors.New("imagetools returned no platforms")
	}
	var platforms []string
	if only != "" {
		platforms = strings.Split(only, ",")
		for _, p := range platforms {
			if _, ok := multi[p]; !ok {
				return imageConfig{}, fmt.Errorf("the image has no %s variant", p)
			}
		}
	} else {
		for p := range multi {
			if strings.HasPrefix(p, "linux/") { // e.g. python:3 also ships windows/amd64 with a different Cmd
				platforms = append(platforms, p)
			}
		}
		if len(platforms) == 0 {
			return imageConfig{}, errors.New("the image has no linux platforms")
		}
		sort.Strings(platforms)
	}
	first := multi[platforms[0]].Config
	for _, p := range platforms[1:] {
		c := multi[p].Config
		if !reflect.DeepEqual(c.Entrypoint, first.Entrypoint) || !reflect.DeepEqual(c.Cmd, first.Cmd) || c.User != first.User {
			return imageConfig{}, fmt.Errorf("platforms %s and %s have different Entrypoint/Cmd/User; wrap them separately with --platform", platforms[0], p)
		}
	}
	return first, nil
}
