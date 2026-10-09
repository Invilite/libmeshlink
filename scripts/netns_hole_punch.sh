#!/usr/bin/env bash
# NAT hole punching end to end, on one machine, with network namespaces (needs root):
#
#         [ inet: 203.0.113.0/24, "the Internet" ]
#           |                 |                  |
#      natA 203.0.113.1    R 203.0.113.10     natB 203.0.113.2
#           |  MASQUERADE                         |  MASQUERADE
#      hostA 10.1.0.2                         hostB 10.2.0.2
#
# R is a public node; A and B sit behind their own NAT (a home router: unsolicited inbound dropped, not reset). Both dial
# R, learn of each other through the mesh, notice they are behind NAT (R reports their public address) and the hole
# punching policy connects them directly. Success = `meshlink map` from R shows a hole punched link.
#
#   sudo scripts/netns_hole_punch.sh                # endpoint-independent NAT: the punch must succeed
#   sudo scripts/netns_hole_punch.sh --symmetric    # MASQUERADE --random (symmetric NAT): the punch must fail, mesh stays whole
#
# MESHLINKD / MESHLINK point at the binaries (default: ../meshlinkd/). TIMEOUT: seconds to wait (default 150).
# Everything (namespaces, processes, temp dir) is removed on exit; KEEP=1 keeps the logs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MESHLINKD="${MESHLINKD:-$SCRIPT_DIR/../../meshlinkd/meshlinkd}"
MESHLINK="${MESHLINK:-$SCRIPT_DIR/../../meshlinkd/meshlink}"
TIMEOUT="${TIMEOUT:-150}"
SYMMETRIC=0
[[ "${1:-}" == "--symmetric" ]] && SYMMETRIC=1

[[ $EUID -eq 0 ]] || { echo "needs root (network namespaces, iptables)"; exit 2; }
for binary in "$MESHLINKD" "$MESHLINK"; do [[ -x "$binary" ]] || { echo "missing $binary (build meshlinkd first)"; exit 2; }; done
command -v iptables >/dev/null || { echo "missing iptables"; exit 2; }

PREFIX="mlpunch$$"
NAMESPACES=(inet r natA hostA natB hostB)
WORK="$(mktemp -d /tmp/meshlink-punch.XXXXXX)"
PIDS=()

ns() { echo "${PREFIX}_$1"; }
in_ns() { local name="$1"; shift; ip netns exec "$(ns "$name")" "$@"; }

cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    for name in "${NAMESPACES[@]}"; do ip netns del "$(ns "$name")" 2>/dev/null || true; done
    if [[ "${KEEP:-0}" == 1 ]]; then echo "logs kept in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# -- Namespaces and links ------------------------------------------------------
for name in "${NAMESPACES[@]}"; do
    ip netns add "$(ns "$name")"
    in_ns "$name" ip link set lo up
done

# "The Internet": a bridge in inet; R, natA and natB hang on it
in_ns inet ip link add br0 type bridge
in_ns inet ip link set br0 up

# veth pair: <left ns>:<left if> <-> <right ns>:<right if>
link() {
    local leftNs="$1" leftIf="$2" rightNs="$3" rightIf="$4"
    ip link add "${PREFIX:0:6}$5a" type veth peer name "${PREFIX:0:6}$5b"
    ip link set "${PREFIX:0:6}$5a" netns "$(ns "$leftNs")"
    ip link set "${PREFIX:0:6}$5b" netns "$(ns "$rightNs")"
    in_ns "$leftNs"  ip link set "${PREFIX:0:6}$5a" name "$leftIf"
    in_ns "$rightNs" ip link set "${PREFIX:0:6}$5b" name "$rightIf"
    in_ns "$leftNs"  ip link set "$leftIf" up
    in_ns "$rightNs" ip link set "$rightIf" up
}

link inet r0 r    wan 1
link inet a0 natA wan 2
link inet b0 natB wan 3
for port in r0 a0 b0; do in_ns inet ip link set "$port" master br0; done

in_ns r ip addr add 203.0.113.10/24 dev wan

# A home router: LAN side, WAN side, MASQUERADE out, nothing unsolicited in (dropped, not reset, like most NATs)
router() {
    local name="$1" wanAddress="$2" lan="$3" host="$4" index="$5"
    in_ns "$name" ip addr add "$wanAddress/24" dev wan
    link "$name" lan "$host" eth0 "$index"
    in_ns "$name" ip addr add "$lan.1/24" dev lan
    in_ns "$host" ip addr add "$lan.2/24" dev eth0
    in_ns "$host" ip route add default via "$lan.1"
    in_ns "$name" sysctl -qw net.ipv4.ip_forward=1
    local masquerade=(-t nat -A POSTROUTING -o wan -j MASQUERADE)
    [[ $SYMMETRIC == 1 ]] && masquerade+=(--random)
    in_ns "$name" iptables "${masquerade[@]}"
    in_ns "$name" iptables -A FORWARD -i lan -o wan -j ACCEPT
    in_ns "$name" iptables -A FORWARD -i wan -o lan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    in_ns "$name" iptables -A FORWARD -i wan -j DROP
    in_ns "$name" iptables -A INPUT -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    in_ns "$name" iptables -A INPUT -i wan -j DROP
}

router natA 203.0.113.1 10.1.0 hostA 4
router natB 203.0.113.2 10.2.0 hostB 5

# -- Nodes ---------------------------------------------------------------------
for node in R A B; do mkdir -p "$WORK/$node"; done
"$MESHLINKD" --create-network-key --state-dir "$WORK/R" >/dev/null
cp -p "$WORK/R/network.key" "$WORK/A/network.key"
cp -p "$WORK/R/network.key" "$WORK/B/network.key"

start_node() {
    local node="$1" namespace="$2"; shift 2
    in_ns "$namespace" "$MESHLINKD" --state-dir "$WORK/$node" --name "$node" --socket "$WORK/$node.sock" --no-discovery -v "$@" >"$WORK/$node.log" 2>&1 &
    PIDS+=($!)
}

start_node R r     -p 8420 --announce 203.0.113.10:8420
sleep 1
start_node A hostA -p 8420 --node 203.0.113.10:8420
start_node B hostB -p 8420 --node 203.0.113.10:8420

map_from_r() { in_ns r "$MESHLINK" --socket "$WORK/R.sock" map "$@" 2>/dev/null || true; }

echo "waiting up to ${TIMEOUT} s for the hole punching policy (attempts every ~20 s once A and B know each other)..."
deadline=$((SECONDS + TIMEOUT))
punched=0
while (( SECONDS < deadline )); do
    if map_from_r | grep -q "^hole punched:"; then punched=1; break; fi
    sleep 5
done

echo
map_from_r
echo
echo "hole punching counters (from each node):"
map_from_r --format json | grep -o '"hole_punch[a-z_]*":[0-9]*' | sort | uniq -c || true
echo
echo "punch log lines:"
grep -h -i "hole punch" "$WORK"/*.log | tail -n 20 || true

# Both stay connected to R either way: a failed punch must not cost the mesh anything
links_to_r=$(map_from_r | grep -c "^  <- " || true)

if [[ $SYMMETRIC == 0 ]]; then
    if (( punched == 1 )); then echo "PASS: A and B punched a direct link through their NATs"; exit 0; fi
    echo "FAIL: no hole punched link within ${TIMEOUT} s"; KEEP=1; exit 1
else
    if (( punched == 0 )) && (( links_to_r >= 2 )); then echo "PASS: symmetric NAT: no punch, both still connected through R"; exit 0; fi
    echo "FAIL: symmetric NAT: punched=$punched, links to R=$links_to_r"; KEEP=1; exit 1
fi
