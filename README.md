# wgwrap

TLDR: Allows you to use WireGuard on any container.

`wgwrap` takes any existing image (debian, alpine, distroless, scratch…) and builds a derived image
that brings up its own `wg0` interface at startup, from a standard wg-quick config, then runs the
image's original entrypoint unchanged. Only that container gets the tunnel. There are no sidecars,
no `network_mode: service:*`, and no changes to the app image.

```bash
mise run build && mise run image   # bin/wgwrap + the localhost/wgwrap-init:<version> image
./bin/wgwrap build nginx:latest -t nginx-wg
docker run --cap-add NET_ADMIN -v ./wg0.conf:/etc/wireguard/wg0.conf:ro nginx-wg
```

## Releases

- It pushes the multi-arch init image to `pkg.bar/wgwrap-init:<tag>` (and `:latest`).
- It attaches `wgwrap` CLI binaries (linux and darwin, amd64 and arm64) to a Forgejo release.
- Those binaries default to that init image, so `--init-image` isn't needed.

## How it works

Every container has its own network namespace. `wgwrap build` generates this Dockerfile:

```dockerfile
FROM localhost/wgwrap-init:<version> AS wgwrap
FROM nginx:latest
COPY --from=wgwrap /wgwrap-init /wgwrap-init
USER root
ENV WGWRAP_USER=""                     # the image's original USER
ENTRYPOINT ["/wgwrap-init","--","/docker-entrypoint.sh"]
CMD ["nginx","-g","daemon off;"]       # re-set, because setting ENTRYPOINT clears it
```

`/wgwrap-init` is a single static Go binary. It needs nothing from the image: no shell, `ip`, `wg`
or libc. At startup it:

1. Parses the wg-quick config.
2. Creates `wg0` _inside the container's namespace_ through netlink and configures keys and peers
   with wgctrl. It adds addresses, routes and (for a full tunnel) the same fwmark policy rules
   `wg-quick` uses. The encrypted UDP traffic leaves through the container's normal `eth0`.
3. Switches to the image's original user (from the image's `/etc/passwd` and `/etc/group`, with
   numeric fallback) and drops `CAP_NET_ADMIN`, so the app can't reconfigure the tunnel (with a full
   tunnel also `CAP_NET_RAW`, see below). It refuses to start if that user could read the config file.
4. Hands off to the original entrypoint:
   - **Kernel mode** (`wireguard` module on the host): `exec`. The app becomes PID 1 and the
     kernel keeps `wg0` alive. No process is left behind.
   - **Userspace mode** (no module; wireguard-go on `/dev/net/tun`): the tunnel lives _in_ the
     wgwrap process, so it can't exec. It stays as a minimal PID 1. It starts the app as a child,
     forwards signals, reaps zombies and exits with the app's exit code (128+N if killed by signal N).
     If the tunnel dies, the app gets SIGTERM, then SIGKILL after `WG_STOP_GRACE`.

## Runtime requirements

| What                                            | Why                                                                                                        |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `--cap-add NET_ADMIN`                           | Always. Creating interfaces and routes needs it. The app doesn't keep it.                                  |
| `modprobe wireguard` on the host                | Kernel mode (the default when available). Containers can't load modules.                                   |
| `--device /dev/net/tun`                         | Userspace mode (the fallback, or `WG_MODE=userspace`).                                                     |
| `--sysctl net.ipv4.conf.all.src_valid_mark=1`   | Full tunnel (`AllowedIPs = 0.0.0.0/0`). `/proc/sys` is read-only in containers.                            |
| `--sysctl net.ipv6.conf.default.disable_ipv6=0` | Only if the config has IPv6 and the container has IPv6 disabled; otherwise IPv6 is skipped with a warning. |

## Environment variables

| Variable                   | Default                   | Meaning                                                                                            |
| -------------------------- | ------------------------- | -------------------------------------------------------------------------------------------------- |
| `WG_CONFIG`                | `/etc/wireguard/wg0.conf` | Path of the wg-quick config.                                                                       |
| `WG_CONFIG_B64`            |                           | The config, base64-encoded. Takes precedence over `WG_CONFIG`. Removed from the app's environment. |
| `WG_INTERFACE`             | `wg0`                     | Interface name.                                                                                    |
| `WG_MODE`                  | `auto`                    | `kernel`, `userspace`, or `auto` (kernel, falling back to userspace if there's no module).         |
| `WG_OPTIONAL`              |                           | `1`: if there's no config, start the app without a tunnel instead of failing.                      |
| `WG_RESOLVE_TIMEOUT`       | `30s`                     | How long to retry resolving `Endpoint` hostnames (container DNS may not be ready yet).             |
| `WG_WAIT_HANDSHAKE`        |                           | e.g. `10s`: wait until a peer handshakes before starting the app.                                  |
| `WG_WAIT_HANDSHAKE_STRICT` |                           | `1`: fail instead of warning when that wait times out.                                             |
| `WG_STOP_GRACE`            | `10s`                     | Userspace mode: time between SIGTERM and SIGKILL when the tunnel dies.                             |
| `WG_DROP_CAPS`             | `1`                       | `0`: let the app keep `CAP_NET_ADMIN` and `CAP_NET_RAW`.                                           |
| `WG_ALLOW_DNS_LEAK`        |                           | `1`: allow a full tunnel without `DNS =` on a network using Docker's resolver (see below).         |
| `WG_LOG`                   | `info`                    | `debug`, `info` or `quiet`. Keys are never logged.                                                 |
| `WGWRAP_USER`              | image's `USER`            | The user the app runs as: `name`, `uid`, `name:group`, `uid:gid`. Set by `wgwrap build`.           |

## Config support

These standard wg-quick keys are supported. Keys are case-insensitive, `#` starts a comment,
lists are comma-separated, and keys may repeat.

- `[Interface]`: `PrivateKey`, `Address` (several, v4 and v6), `DNS`, `MTU` (default 1420), `ListenPort`,
  `FwMark`, `Table` (`auto`, `off`, `main` or a number).
- `[Peer]`: `PublicKey`, `PresharedKey`, `Endpoint` (`host:port` or `[v6]:port`), `AllowedIPs`, `PersistentKeepalive`.

`PreUp`, `PostUp`, `PreDown`, `PostDown` and `SaveConfig` are ignored with a warning, because there
may be no shell to run them. Errors report the line number.

Routing follows wg-quick. Each `AllowedIPs` range gets a route via `wg0`. A `/0` turns on full-tunnel
policy routing:

- fwmark 51820 (or `FwMark`), and a default route in table 51820;
- `ip rule not fwmark 51820 table 51820`;
- `ip rule table main suppress_prefixlength 0`, evaluated first, so the container's subnet and
  Docker's DNS keep working.
- a kill switch, `ip rule not fwmark 51820 prohibit`, evaluated last. Unmarked traffic that the tunnel
  table can't route is refused instead of leaving through `eth0`. That covers sockets bound to `eth0`
  with `SO_BINDTODEVICE` (allowed for any user), and a deleted `wg0`. `CAP_NET_RAW` is also dropped,
  so the app can't send raw frames out of `eth0` either. Unprivileged ICMP ping still works.
  One gap remains: when a bound socket's route lookup fails, the kernel assumes the destination is
  on-link and ARPs for it on `eth0`. The Docker host answers for its own addresses, so the app can
  still reach the host itself (e.g. `172.17.0.1` or its LAN IP). It can't reach anything beyond the host.

A full tunnel also needs `DNS =` when the container uses Docker's embedded resolver (`127.0.0.11`, on
any user-defined network). That resolver forwards queries from the host, outside the tunnel, so wgwrap
refuses to start without `DNS =` unless `WG_ALLOW_DNS_LEAK=1`.

With `Table = N`, every route goes in table N and no rules are added. `Table = off` adds no routes.
`DNS` rewrites `/etc/resolv.conf`: IPs become `nameserver` lines, anything else becomes `search`.

## Examples

Plain Docker, with the config mounted, in kernel mode:

```bash
wgwrap build nginx:latest -t nginx-wg
docker run -d --cap-add NET_ADMIN -v ./wg0.conf:/etc/wireguard/wg0.conf:ro nginx-wg
```

Userspace mode, full tunnel, config from an env var:

```bash
docker run --cap-add NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  -e WG_MODE=userspace -e WG_CONFIG_B64="$(base64 -w0 wg0-full.conf)" alpine-wg wget -qO- ifconfig.me
```

Compose: see [examples/compose.yaml](examples/compose.yaml), [examples/wg0.conf](examples/wg0.conf)
(split tunnel) and [examples/wg0-full.conf](examples/wg0-full.conf) (full tunnel).

## The `wgwrap` CLI

```
wgwrap build <source-image> -t <tag> [--platform linux/amd64,linux/arm64] [--push]
             [--init-image IMAGE] [--config wg0.conf] [--optional] [--dry-run]
wgwrap inspect <image>     # original vs wrapped entrypoint/cmd/user
wgwrap version
```

- It reads the source image's config with `docker buildx imagetools inspect`, which needs no pull and
  handles multi-arch. Local-only images fall back to `docker image inspect`.
- If the platforms of a multi-arch image have different Entrypoint/Cmd/User, the build fails.
  Pick platforms with `--platform`.
- Builds with `docker buildx build`, using `--load` by default or `--push`.
- Wrapping an already-wrapped image re-wraps the original entrypoint instead of stacking two inits.
- `--config` bakes the config into the image (mode 0600), private key included. Only do this for
  images you never push anywhere shared.
- `--optional` sets `WG_OPTIONAL=1`, so the image also runs without a config.
- `--init-image` defaults to `localhost/wgwrap-init:<version>`. The `localhost/` prefix means it is
  never pulled from Docker Hub by accident. Build it with `mise run image`, or publish it
  multi-arch (amd64, arm64, arm/v7) with `INIT_IMAGE=pkg.bar/wgwrap-init mise run image-multiarch`.
  Bake that name in with `INIT_IMAGE=pkg.bar/wgwrap-init mise run build`.
- With `--platform`, the init image must have those platforms too: use `mise run image-multiarch`, or
  `docker buildx build --platform ... --load .` on the containerd image store.

## Gotchas

- **Don't use `--user` / compose `user:`.** wgwrap must start as root to create the interface, and
  it fails with an explanation if it doesn't. Use `-e WGWRAP_USER=1000` instead. wgwrap switches to
  that user after setup, the same way Docker would (unknown numeric uid → gid 0, primary gid in groups).
- **`--entrypoint` bypasses wgwrap.** Overriding the entrypoint skips the tunnel. Override CMD
  (the arguments after the image name) instead.
- **A full tunnel breaks `-p` published ports.** Replies to connections that arrive on `eth0` from
  outside the container's subnet match the default route in table 51820, so they go into the
  tunnel. Use a split tunnel for services that must stay reachable through `-p`, or reach them over
  the tunnel.
- **Subnet clashes.** If `AllowedIPs` overlaps a Docker bridge subnet (often `172.17–31.x`), the
  more specific route wins and you can lose the container's own network or DNS (`127.0.0.11`).
  Pick non-overlapping ranges.
- **MTU.** The default 1420 works over a 1500-byte path. Behind another tunnel, or on PPPoE,
  lower it (e.g. 1380) if large transfers hang.
- **NAT.** A container behind NAT can't receive the first packet. Set `PersistentKeepalive = 25` so
  the peer learns its endpoint and the NAT mapping stays open.
- **Who can read the private key.** A non-root app never gets it: wgwrap refuses to start if the
  app's user could read the config file (`chmod 600` it, owned by a different uid). An app running as
  root can read any file in the container, so for root apps pass the config as `WG_CONFIG_B64` (removed
  from the app's environment). Anyone with access to `docker inspect` can still see it there.
- **The peer is inside your perimeter.** There is no firewall on `wg0`: the peer can reach every port
  the app listens on. With a full tunnel it can also send packets from any source address. Don't
  protect services inside the container with source-IP allowlists. Only peer with servers you trust
  like your router.
- **Baked-in keys.** `--config` puts the private key in an image layer. Prefer mounting the config or
  using `WG_CONFIG_B64` from a secret store.
- **Userspace mode needs a writable `/var/run`** for the brief configuration socket. It's removed
  once setup is done. With `--read-only`, add `--tmpfs /var/run/wireguard`.
- **Restart.** The interface lives in the container's namespace and goes away with it. On a restart
  it is created again.

## Development

```bash
mise run build ::: test ::: lint  # unit tests: parser, Dockerfile generation, user resolution, exit codes
mise run integration      # Docker end-to-end: needs Docker + buildx, pulls nginx/alpine/distroless
ONLY="nginx full" test/integration.sh   # run a subset
# Docker Hub rate-limited? Pull the base images through a mirror:
NGINX_IMAGE=mirror.gcr.io/library/nginx ALPINE_IMAGE=mirror.gcr.io/library/alpine test/integration.sh
GO_IMAGE=mirror.gcr.io/library/golang:1.26.11-alpine@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab mise run image
```

The integration test runs a wrapped alpine as the server peer, and wraps and checks these:

- nginx in kernel mode;
- alpine in kernel and userspace mode;
- nginx-unprivileged (uid/gid/groups match the unwrapped image);
- a distroless static binary;
- `docker stop` exit codes;
- error messages;
- a full tunnel, checked against an echo service on an `--internal` network that only the server can reach.

Without the wireguard module, kernel-mode tests are skipped.
