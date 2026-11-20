#!/usr/bin/env bash
# End-to-end tests for wgwrap. Needs Docker (with buildx) and network access to pull images.
#
#   INIT_IMAGE=localhost/wgwrap-init:dev WGWRAP=./bin/wgwrap test/integration.sh
#   ONLY="nginx alpine_userspace" test/integration.sh   # run a subset
#   KEEP=1 test/integration.sh                           # leave containers for debugging
#   NGINX_IMAGE=mirror.gcr.io/library/nginx ALPINE_IMAGE=mirror.gcr.io/library/alpine  # dodge Docker Hub rate limits
#
# Topology: a "server" peer (a wrapped alpine) on network $P-uplink, plus an --internal
# network $P-egress that only the server is on. An echo service shares the server's network
# namespace, so it is reachable at the server's tunnel IP (10.99.0.1) and its egress IP.
set -eu  # no pipefail: `cmd | grep -q` would fail on SIGPIPE
cd "$(dirname "$0")/.."

WGWRAP=${WGWRAP:-./bin/wgwrap}
INIT_IMAGE=${INIT_IMAGE:-localhost/wgwrap-init:dev}
P=wgwraptest
WGNET=10.99.0
tmp=$(mktemp -d)
pass=0 fail=0 skipped=0
failed=()

log() { printf '\033[1m==> %s\033[0m\n' "$*"; }
ok() { pass=$((pass + 1)); printf '  \033[32mok\033[0m   %s\n' "$*"; }
bad() { fail=$((fail + 1)); failed+=("$current: $*"); printf '  \033[31mFAIL\033[0m %s\n' "$*"; }
skip() { skipped=$((skipped + 1)); printf '  \033[33mskip\033[0m %s\n' "$*"; }
check() { # check "description" cmd...
	local d=$1; shift
	local o
	if o=$("$@" 2>&1); then ok "$d"; else bad "$d"; printf "%s\n" "$o" | sed 's/^/       /' | tail -15; fi
}

cleanup() {
	if [[ -n ${KEEP:-} ]]; then echo "KEEP set: leaving containers, config in $tmp"; return; fi
	docker ps -aq --filter label=$P | xargs -r docker rm -f >/dev/null
	docker network rm $P-uplink $P-egress >/dev/null 2>&1 || true
	docker volume rm $P-conf >/dev/null 2>&1 || true
	rm -rf "$tmp"
}
trap cleanup EXIT
cleanup_containers() { docker ps -aq --filter label=$P | xargs -r docker rm -f >/dev/null; }
cleanup_containers
docker network rm $P-uplink $P-egress >/dev/null 2>&1 || true
docker volume rm $P-conf >/dev/null 2>&1 || true

# Kernel mode needs the wireguard module on the host; otherwise test userspace only.
if [[ -d /sys/module/wireguard ]] || modprobe wireguard 2>/dev/null; then KERNEL=1; else KERNEL=; fi
SERVER_MODE=$([[ -n $KERNEL ]] && echo kernel || echo userspace)

# ---- keys and configs ----
CGO_ENABLED=0 go build -o "$tmp/wgkey" ./test/wgkey
CGO_ENABLED=0 go build -o "$tmp/echo" ./test/echo
read -r SRV_PRIV SRV_PUB < <("$tmp/wgkey")
declare -A PRIV PUB
CLIENTS=(nginx alpine_k alpine_u unpriv distroless stop full v6 death tty baked)
srvconf="[Interface]
PrivateKey = $SRV_PRIV
Address = $WGNET.1/24
ListenPort = 51820
"
n=2
declare -A IP
for c in "${CLIENTS[@]}"; do
	read -r PRIV[$c] PUB[$c] < <("$tmp/wgkey")
	IP[$c]=$WGNET.$n
	srvconf+="
[Peer]
PublicKey = ${PUB[$c]}
AllowedIPs = $WGNET.$n/32
"
	n=$((n + 1))
done
printf '%s' "$srvconf" >"$tmp/server.conf"

clientconf() { # clientconf name allowedips
	cat >"$tmp/$1.conf" <<-EOF
	[Interface]
	PrivateKey = ${PRIV[$1]}
	Address = ${IP[$1]}/24
	PostUp = echo this is ignored

	[Peer]
	PublicKey = $SRV_PUB
	Endpoint = $P-server:51820
	AllowedIPs = $2
	PersistentKeepalive = 5
	EOF
	# A full tunnel on Docker's resolver needs DNS= (no DNS server there; tests use IPs).
	[[ $2 != */0* ]] || sed -i "/^Address/a DNS = $WGNET.1" "$tmp/$1.conf"
	chmod 600 "$tmp/$1.conf" # wgwrap refuses configs the app user could read
	echo "$tmp/$1.conf"
}

# ---- images ----
log "building images"
"$WGWRAP" build "${ALPINE_IMAGE:-alpine:latest}" -t $P-alpine-wg --init-image "$INIT_IMAGE" >/dev/null 2>"$tmp/build.log" || { cat "$tmp/build.log"; exit 1; }
cat >"$tmp/Dockerfile.echo" <<EOF
FROM gcr.io/distroless/static:nonroot
COPY echo /echo
ENTRYPOINT ["/echo"]
EOF
docker buildx build -q --load -t $P-echo -f "$tmp/Dockerfile.echo" "$tmp" >/dev/null

docker network create --subnet 172.30.99.0/24 $P-uplink >/dev/null
docker network create --internal --subnet 172.30.98.0/24 $P-egress >/dev/null

run() { docker run -d --label $P "$@" >/dev/null; }
# mnt file: copy a config into the $P-conf volume (keeping its mode) and print the docker run
# args that use it. Bind-mounting $tmp would break when the daemon is remote, e.g. a CI job
# container talking to the VM's Docker through its socket.
mnt() {
	local name; name=$(basename "$1")
	docker run --rm -i --entrypoint sh -v $P-conf:/conf $P-alpine-wg -c "cat >/conf/$name && chmod $(stat -c %a "$1") /conf/$name" <"$1"
	echo "-v $P-conf:/conf:ro -e WG_CONFIG=/conf/$name"
}

log "starting server peer ($SERVER_MODE mode)"
run --name $P-server --hostname $P-server --network $P-uplink --cap-add NET_ADMIN --device /dev/net/tun \
	-e WG_MODE=$SERVER_MODE $(mnt "$tmp/server.conf") $P-alpine-wg sleep infinity
docker network connect $P-egress $P-server
run --name $P-server-echo --network container:$P-server $P-echo
EGRESS_IP=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$P-egress\").IPAddress}}" $P-server)
sleep 1
docker logs $P-server 2>&1 | grep -q "wg0 up" || { docker logs $P-server; echo "server didn't come up"; exit 1; }

# wait_up container: wait until wgwrap logged the summary (or the container died).
wait_up() {
	for _ in $(seq 1 60); do
		docker logs "$1" 2>&1 | grep -q "wg0 up" && return 0
		[[ $(docker inspect -f '{{.State.Running}}' "$1") == true ]] || break
		sleep 0.5
	done
	docker logs "$1" 2>&1 | tail -20
	return 1
}
srv() { docker exec $P-server "$@"; }
# retry: tunnel traffic right after startup may race the first handshake.
retry() { for _ in 1 2 3 4 5 6 7 8 9 10; do "$@" && return 0; sleep 1; done; "$@"; }
status_of() { docker exec "$1" sh -c "grep -E '^($2):' /proc/$3/status" 2>/dev/null; }
# no_net_admin container pid [mask]: capability bits cleared? NET_ADMIN is 12 (0x1000), NET_RAW 13 (0x2000).
no_net_admin() {
	local st; st=$(docker exec "$1" cat /proc/"$2"/status)
	local eff bnd m=${3:-0x1000}
	eff=$(awk '/^CapEff/{print $2}' <<<"$st"); bnd=$(awk '/^CapBnd/{print $2}' <<<"$st")
	(((0x$eff & m) == 0 && (0x$bnd & m) == 0)) || { echo "CapEff=$eff CapBnd=$bnd"; return 1; }
}
uidline() { docker exec "$1" sh -c "grep -E '^(Uid|Gid|Groups):' /proc/$2/status | tr -s '\t ' ' '"; }

same() { [[ -n $1 && $1 == "$2" ]]; } # non-empty and equal
should_run() { [[ -z ${ONLY:-} || " $ONLY " == *" $1 "* ]]; }

# ---------------------------------------------------------------------------------------
test_nginx() {
	[[ -n $KERNEL ]] || { skip "nginx kernel mode: no wireguard module"; return; }
	check "wrap nginx" "$WGWRAP" build "${NGINX_IMAGE:-nginx:latest}" -t $P-nginx-wg --init-image "$INIT_IMAGE"
	run --name $P-nginx --network $P-uplink --cap-add NET_ADMIN -e WG_WAIT_HANDSHAKE=15s \
		$(mnt "$(clientconf nginx $WGNET.0/24)") $P-nginx-wg
	check "nginx came up in kernel mode" wait_up $P-nginx
	check "PostUp ignored with a warning" sh -c "docker logs $P-nginx 2>&1 | grep -q 'postup is ignored'"
	check "server -> nginx over the tunnel" retry srv sh -c "wget -T 3 -qO- http://${IP[nginx]}/ | grep -q 'Welcome to nginx'"
	check "nginx -> server echo over the tunnel" retry docker exec $P-nginx sh -c "curl -sf http://$WGNET.1:8080/ | grep -q 'remote=${IP[nginx]} '"
	check "nginx is PID 1 (exec, no supervisor)" sh -c "docker exec $P-nginx cat /proc/1/comm | grep -q nginx"
	check "app has no CAP_NET_ADMIN" no_net_admin $P-nginx 1
	check "re-wrap doesn't stack inits" sh -c "'$WGWRAP' build $P-nginx-wg -t x --dry-run --init-image '$INIT_IMAGE' 2>/dev/null | grep -qx 'ENTRYPOINT \[\"/wgwrap-init\",\"--\",\"/docker-entrypoint.sh\"\]'"
}

test_alpine_kernel() {
	[[ -n $KERNEL ]] || { skip "alpine kernel mode: no wireguard module"; return; }
	run --name $P-alpine-k --network $P-uplink --cap-add NET_ADMIN -e WG_MODE=kernel \
		$(mnt "$(clientconf alpine_k $WGNET.0/24)") $P-alpine-wg sleep infinity
	check "alpine came up in kernel mode" sh -c "wait_up() { :; }; for i in \$(seq 30); do docker logs $P-alpine-k 2>&1 | grep -q 'wg0 up (kernel mode)' && exit 0; sleep 0.5; done; exit 1"
	check "alpine -> server ping" retry docker exec $P-alpine-k ping -c1 -W2 $WGNET.1
	check "server -> alpine ping" retry srv ping -c1 -W2 ${IP[alpine_k]}
	check "app has no CAP_NET_ADMIN" no_net_admin $P-alpine-k 1
}

test_alpine_userspace() {
	run --name $P-alpine-u --network $P-uplink --cap-add NET_ADMIN --device /dev/net/tun -e WG_MODE=userspace \
		$(mnt "$(clientconf alpine_u $WGNET.0/24)") $P-alpine-wg sleep infinity
	check "alpine came up in userspace mode" sh -c "for i in \$(seq 30); do docker logs $P-alpine-u 2>&1 | grep -q 'wg0 up (userspace mode)' && exit 0; sleep 0.5; done; exit 1"
	check "alpine -> server ping" retry docker exec $P-alpine-u ping -c1 -W2 $WGNET.1
	check "server -> alpine ping" retry srv ping -c1 -W2 ${IP[alpine_u]}
	check "PID 1 is the wgwrap supervisor" sh -c "docker exec $P-alpine-u cat /proc/1/comm | grep -q wgwrap-init"
	local pid; pid=$(docker exec $P-alpine-u pidof sleep)
	check "app has no CAP_NET_ADMIN" no_net_admin $P-alpine-u "$pid"
	check "UAPI socket removed after setup" docker exec $P-alpine-u sh -c "! test -e /var/run/wireguard/wg0.sock"
}

test_unpriv() {
	[[ -n $KERNEL ]] || { skip "non-root image: no wireguard module"; return; }
	local img=${UNPRIV_IMAGE:-ghcr.io/nginx/nginx-unprivileged:latest}
	check "wrap $img" "$WGWRAP" build $img -t $P-unpriv-wg --init-image "$INIT_IMAGE"
	run --name $P-unpriv-ref $img
	run --name $P-unpriv --network $P-uplink --cap-add NET_ADMIN \
		$(mnt "$(clientconf unpriv $WGNET.0/24)") $P-unpriv-wg
	check "unprivileged nginx came up" wait_up $P-unpriv
	check "server -> nginx-unprivileged :8080" retry srv sh -c "wget -T 3 -qO- http://${IP[unpriv]}:8080/ | grep -q 'Welcome to nginx'"
	check "nginx-unprivileged can write its logs and keeps running" sh -c "docker exec $P-unpriv true && ! docker logs $P-unpriv 2>&1 | grep -q 'Permission denied'"
	sleep 1
	local want got
	want=$(uidline $P-unpriv-ref 1); got=$(uidline $P-unpriv 1)
	check "runs as the original user ($(echo $want | tr '\n' ' '))" same "$want" "$got"
	[[ $want == "$got" ]] || echo "       want: $want / got: $got"
	# nginx overwrites its environ (setproctitle), so compare via `env` as the CMD instead.
	check "HOME matches the unwrapped image" same "$(docker run --rm --label $P $img env | grep ^HOME=)" "$(docker run --rm --label $P -e WG_OPTIONAL=1 $P-unpriv-wg env 2>/dev/null | grep ^HOME=)"
}

test_distroless() {
	[[ -n $KERNEL ]] || { skip "distroless: no wireguard module"; return; }
	check "wrap a distroless image" "$WGWRAP" build $P-echo -t $P-echo-wg --init-image "$INIT_IMAGE"
	run --name $P-distroless --network $P-uplink --cap-add NET_ADMIN \
		$(mnt "$(clientconf distroless $WGNET.0/24)") $P-echo-wg
	check "distroless came up" wait_up $P-distroless
	local ref got
	ref=$(docker run --rm --label $P --network $P-uplink --name $P-distroless-ref -d $P-echo >/dev/null; sleep 1;
		srv wget -T 3 -qO- "http://$(docker inspect -f "{{(index .NetworkSettings.Networks \"$P-uplink\").IPAddress}}" $P-distroless-ref):8080/" | sed 's/remote=[^ ]* //')
	docker rm -f $P-distroless-ref >/dev/null
	check "server -> distroless app over the tunnel" retry srv sh -c "wget -T 3 -qO- http://${IP[distroless]}:8080/ >/dev/null"
	got=$(srv wget -T 3 -qO- "http://${IP[distroless]}:8080/" | sed 's/remote=[^ ]* //')
	check "runs as the original user ($ref)" same "$ref" "$got"
	[[ $ref == "$got" ]] || echo "       want: $ref / got: $got"
}

test_stop() {
	run --name $P-stop --network $P-uplink --cap-add NET_ADMIN --device /dev/net/tun -e WG_MODE=userspace \
		$(mnt "$(clientconf stop $WGNET.0/24)") \
		$P-alpine-wg sh -c 'trap "echo got TERM; exit 42" TERM; while true; do sleep 0.2; done'
	check "came up" wait_up $P-stop
	docker stop -t 10 $P-stop >/dev/null
	check "app got SIGTERM" sh -c "docker logs $P-stop 2>&1 | grep -q 'got TERM'"
	check "container exits with the app's code (42)" test "$(docker inspect -f '{{.State.ExitCode}}' $P-stop)" == 42
	local code
	code=$(docker run --rm --label $P --cap-add NET_ADMIN --device /dev/net/tun -e WG_MODE=userspace --network $P-uplink \
		$(mnt "$tmp/stop.conf") $P-alpine-wg sh -c 'kill -KILL $$' >/dev/null 2>&1; echo $?) || true
	check "killed app maps to 128+9" test "$code" == 137
}

test_errors() {
	clientconf stop $WGNET.0/24 >/dev/null # also needed when ONLY skips test_stop
	local out
	out=$(docker run --rm --label $P --network $P-uplink $(mnt "$tmp/stop.conf") $P-alpine-wg true 2>&1) && bad "no NET_ADMIN should fail"
	check "missing NET_ADMIN explains the fix" grep -q -- "--cap-add NET_ADMIN" <<<"$out"
	out=$(docker run --rm --label $P $P-alpine-wg true 2>&1) && bad "no config should fail"
	check "missing config explains the fix" grep -q "WG_OPTIONAL=1" <<<"$out"
	out=$(docker run --rm --label $P --cap-add NET_ADMIN -e WG_MODE=userspace $(mnt "$tmp/stop.conf") $P-alpine-wg true 2>&1) && bad "userspace without tun should fail"
	check "missing /dev/net/tun explains the fix" grep -q -- "--device /dev/net/tun" <<<"$out"
	check "WG_OPTIONAL=1 without config runs the app" sh -c "docker run --rm --label $P -e WG_OPTIONAL=1 $P-alpine-wg echo hello-app 2>&1 | grep -q hello-app"
	out=$(docker run --rm --label $P --user 1000 $P-alpine-wg true 2>&1) && bad "--user should fail"
	check "--user explains WGWRAP_USER" grep -q "WGWRAP_USER=1000" <<<"$out"
	check "WGWRAP_USER=1234 runs the app as 1234 with gid 0, like docker --user" sh -c \
		"docker run --rm --label $P -e WG_OPTIONAL=1 -e WGWRAP_USER=1234 $P-alpine-wg id | grep -q 'uid=1234 gid=0'"
	check "WG_CONFIG_B64 is not visible to the app" sh -c \
		"docker run --rm --label $P --cap-add NET_ADMIN --network $P-uplink --device /dev/net/tun -e WG_CONFIG_B64=$(base64 -w0 "$tmp/stop.conf") $P-alpine-wg env 2>/dev/null | grep -c WG_CONFIG_B64 | grep -qx 0"
	cp "$tmp/stop.conf" "$tmp/open.conf"
	chmod 644 "$tmp/open.conf"
	out=$(docker run --rm --label $P --network $P-uplink --cap-add NET_ADMIN -e WGWRAP_USER=2000 \
		$(mnt "$tmp/open.conf") $P-alpine-wg true 2>&1) && bad "app-readable config should fail"
	check "config readable by the app user is refused" grep -q "readable by the app user 2000" <<<"$out"
	out=$(docker run --rm --label $P --network $P-uplink --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun \
		-e WG_CONFIG_B64="$(base64 -w0 "$tmp/stop.conf")" $P-alpine-wg true 2>&1) && bad "unable to drop NET_ADMIN should fail"
	check "can't drop NET_ADMIN (no SETPCAP): refuses to start" grep -q "drop CAP_NET_ADMIN" <<<"$out"
	check "--cap-drop ALL without a tunnel still runs" docker run --rm --label $P --cap-drop ALL -e WG_OPTIONAL=1 $P-alpine-wg true
	check "parse errors don't echo the line (it may hold a key)" sh -c \
		"out=\$(docker run --rm --label $P -e WG_CONFIG_B64=$(printf '[Interface]\nPrivateKey %s\n' "${PRIV[stop]}" | base64 -w0) $P-alpine-wg true 2>&1); echo \"\$out\" | grep -q 'expected key = value' && ! echo \"\$out\" | grep -qiF -- '${PRIV[stop]:0:12}'"
}

test_full() {
	[[ -n $KERNEL ]] || { skip "full tunnel (kernel): no wireguard module"; return; }
	run --name $P-full --network $P-uplink --cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 \
		$(mnt "$(clientconf full 0.0.0.0/0)") $P-alpine-wg sleep infinity
	check "full-tunnel client came up" wait_up $P-full
	check "no src_valid_mark warning with --sysctl" sh -c "! docker logs $P-full 2>&1 | grep -q src_valid_mark"
	# The egress network is internal and the client isn't on it: only the tunnel can reach it.
	check "egress goes through the server (echo sees the tunnel IP)" retry docker exec $P-full sh -c \
		"wget -T 3 -qO- http://$EGRESS_IP:8080/ | grep -q 'remote=${IP[full]} '"
	check "handshake survives (endpoint traffic bypasses the tunnel)" docker exec $P-full ping -c1 -W2 $WGNET.1
	check "docker DNS still works (more-specific main routes win)" docker exec $P-full nslookup $P-server 127.0.0.11
	check "DNS= rewrote resolv.conf" docker exec $P-full grep -qx "nameserver $WGNET.1" /etc/resolv.conf
	check "app has neither NET_ADMIN nor NET_RAW" no_net_admin $P-full 1 0x3000

	# Kill switch: a socket bound to eth0 (SO_BINDTODEVICE, no privileges needed) must not get out.
	# The target must be off-host: for a socket bound to a device the kernel falls back to ARPing the
	# destination on eth0, and the Docker host answers that for its own addresses (see README).
	# The control step needs internet access to prove the test can see a leak at all.
	local host_ip=1.1.1.1
	check "kill switch: ping bound to eth0 is refused" docker exec -u 2000 $P-full sh -c "! ping -c1 -W2 -I eth0 $host_ip"
	docker exec $P-full ip rule del pref 32002
	check "  control: without the kill-switch rule it leaks" docker exec -u 2000 $P-full ping -c1 -W2 -I eth0 "$host_ip"
	docker rm -f $P-full >/dev/null

	local full=(docker run --rm --label $P --network $P-uplink --cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 -e WG_LOG=quiet)
	check "root app without NET_RAW can still ping through the tunnel" retry "${full[@]}" $(mnt "$tmp/full.conf") $P-alpine-wg ping -c1 -W3 $WGNET.1
	sed '/^DNS/d' "$tmp/full.conf" >"$tmp/full-nodns.conf"
	chmod 600 "$tmp/full-nodns.conf"
	local out
	out=$("${full[@]}" $(mnt "$tmp/full-nodns.conf") $P-alpine-wg true 2>&1) && bad "full tunnel without DNS= should fail"
	check "full tunnel without DNS= on Docker's resolver is refused" grep -q WG_ALLOW_DNS_LEAK <<<"$out"
	check "  ... unless WG_ALLOW_DNS_LEAK=1" "${full[@]}" -e WG_ALLOW_DNS_LEAK=1 $(mnt "$tmp/full-nodns.conf") $P-alpine-wg true
}

test_ipv6() {
	[[ -n $KERNEL ]] || { skip "ipv6 (kernel): no wireguard module"; return; }
	clientconf v6 "0.0.0.0/0, ::/0" >/dev/null
	sed -i "s|^Address = .*|&, fd99::${IP[v6]##*.}/64|" "$tmp/v6.conf"
	run --name $P-v6 --network $P-uplink --cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 \
		$(mnt "$tmp/v6.conf") $P-alpine-wg sleep infinity
	check "dual-stack full tunnel came up" wait_up $P-v6
	check "IPv6 address and rules installed" docker exec $P-v6 sh -c "ip -6 addr show dev wg0 | grep -q fd99:: && ip -6 rule | grep -q 51820"
	check "IPv4 egress still goes through the tunnel" retry docker exec $P-v6 sh -c "wget -T 3 -qO- http://$EGRESS_IP:8080/ | grep -q 'remote=${IP[v6]} '"
	docker rm -f $P-v6 >/dev/null
	local out
	out=$(docker run --rm --label $P --network $P-uplink --cap-add NET_ADMIN --sysctl net.ipv4.conf.all.src_valid_mark=1 \
		--sysctl net.ipv6.conf.all.disable_ipv6=1 --sysctl net.ipv6.conf.default.disable_ipv6=1 \
		$(mnt "$tmp/v6.conf") $P-alpine-wg ip addr show dev wg0 2>&1)
	check "IPv6 disabled: warns" grep -q "IPv6 is disabled" <<<"$out"
	check "IPv6 disabled: still comes up with IPv4" grep -q "inet ${IP[v6]}/" <<<"$out"
	check "no IPv6 warning for an IPv4-only config" sh -c "! docker logs $P-server 2>&1 | grep -q 'IPv6 is disabled'"
}

test_death() {
	run --name $P-death --network $P-uplink --cap-add NET_ADMIN --device /dev/net/tun -e WG_MODE=userspace -e WG_STOP_GRACE=2s \
		$(mnt "$(clientconf death $WGNET.0/24)") $P-alpine-wg sh -c 'trap "" TERM; sleep 300'
	check "came up" wait_up $P-death
	docker exec $P-death ip link del wg0
	check "tunnel death: container exits 1 after TERM + grace + KILL" sh -c "timeout 20 docker wait $P-death | grep -qx 1"
	check "tunnel death is logged" sh -c "docker logs $P-death 2>&1 | grep -q 'WireGuard device stopped' && docker logs $P-death 2>&1 | grep -q SIGKILL"
}

test_tty() {
	local base=(docker run --rm -t --label $P --network $P-uplink --cap-add NET_ADMIN --device /dev/net/tun -e WG_MODE=userspace
		-e WG_LOG=quiet $(mnt "$(clientconf tty $WGNET.0/24)"))
	check "docker run -t passes the TTY through (userspace supervisor)" sh -c "$(printf '%q ' "${base[@]}") $P-alpine-wg tty | grep -q '^/dev/pts/'"
	check "... also for a non-root WGWRAP_USER, including /dev/stderr" sh -c \
		"$(printf '%q ' "${base[@]}") -e WGWRAP_USER=2000 $P-alpine-wg sh -c 'tty && echo err-ok >/dev/stderr' | tr -d '\r' | grep -qx err-ok"
}

test_baked() {
	clientconf baked $WGNET.0/24 >/dev/null
	sed -i "/^Address/a DNS = $WGNET.1, corp.internal" "$tmp/baked.conf"
	# Building from the already-wrapped alpine also exercises the re-wrap path.
	check "wrap with --config and --optional" "$WGWRAP" build $P-alpine-wg -t $P-baked --config "$tmp/baked.conf" --optional --init-image "$INIT_IMAGE"
	run --name $P-baked --network $P-uplink --cap-add NET_ADMIN --device /dev/net/tun $P-baked sleep infinity
	check "baked config comes up without a mount" wait_up $P-baked
	check "server -> baked ping" retry srv ping -c1 -W2 ${IP[baked]}
	check "DNS= rewrote resolv.conf" docker exec $P-baked sh -c "grep -qx 'nameserver $WGNET.1' /etc/resolv.conf && grep -qx 'search corp.internal' /etc/resolv.conf"
	check "baked config is mode 0600" sh -c "docker exec $P-baked stat -c %a /etc/wireguard/wg0.conf | grep -qx 600"
	check "--optional image runs without a config" sh -c "docker run --rm --label $P -e WG_CONFIG=/nope $P-baked echo opt-ok 2>&1 | grep -q opt-ok"
}

for t in nginx alpine_kernel alpine_userspace unpriv distroless stop errors full ipv6 death tty baked; do
	should_run "$t" || continue
	current=$t
	log "$t"
	"test_$t" || bad "test function crashed"
done

echo
log "passed $pass, failed $fail, skipped $skipped"
for f in "${failed[@]}"; do echo "  FAIL $f"; done
((fail == 0))
