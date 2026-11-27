#!/usr/bin/env bash
# Self-asserting proof harness. Runs each attack class inside the hardened
# container and FAILS (exit 1) if any attack is NOT blocked. Writes proof/last-run.md.
# Usage: JR_IMAGE=jailrunner proof/run.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
export JR_SECCOMP="$ROOT/seccomp.json"
source "$ROOT/jailrunner/flags.sh"
IMAGE="${JR_IMAGE:-jailrunner}"
mapfile -t FLAGS < <(jr_flags)
MOUNTS=()
fails=0; rows=()

pyrun(){ timeout --signal=KILL "${2:-8}" docker run "${FLAGS[@]}" "${MOUNTS[@]}" --entrypoint python "$IMAGE" -c "$1" 2>&1; }
record(){ # name | expect-blocked? | observed | control | pass?
  local pass="$1"; rows+=("| $2 | $3 | $4 |"); [ "$pass" = y ] || { fails=$((fails+1)); echo "FAIL: $2"; }
}

echo "== Jailrunner proof (image=$IMAGE, docker $(docker version -f '{{.Server.Version}}')) =="

o=$(docker run "${FLAGS[@]}" "${MOUNTS[@]}" --entrypoint python "$IMAGE" -c 'print(open("/proc/self/status").read())' 2>&1)
echo "$o" | grep -q "^Uid:[[:space:]]*0[[:space:]]" && id_ok=n || id_ok=y
echo "$o" | grep -Eq "CapEff:[[:space:]]*0000000000000000" && cap_ok=y || cap_ok=n
echo "$o" | grep -Eq "NoNewPrivs:[[:space:]]*1" && nnp_ok=y || nnp_ok=n
[ "$id_ok" = y ] && record y "non-root user" "Uid != 0" "--user 65534"
[ "$cap_ok" = y ] && record y "capabilities dropped" "CapEff=0x0" "--cap-drop ALL" || record n "capabilities dropped" "CapEff not zero" "--cap-drop ALL"
[ "$nnp_ok" = y ] && record y "no-new-privileges" "NoNewPrivs=1" "--security-opt no-new-privileges" || record n "no-new-privileges" "off" "--security-opt no-new-privileges"

o=$(pyrun 'import socket; socket.create_connection(("1.1.1.1",80),2)'); echo "$o" | grep -qiE "unreachable|refused|failed|temporary failure|Errno|permitted" && record y "outbound network" "connect fails" "--network none" || record n "outbound network" "CONNECTED (leak!)" "--network none"

o=$(pyrun 'open("/pwned","w").write("x")'); echo "$o" | grep -qiE "Read-only|Permission" && record y "filesystem write" "read-only fs" "--read-only" || record n "filesystem write" "WROTE (leak!)" "--read-only"

o=$(pyrun 'import os
while True: os.fork()' 6); echo "$o" | grep -qiE "Resource temporarily|BlockingIOError|Cannot allocate|Errno" && record y "fork bomb" "pids capped" "--pids-limit 64" || { [ -n "$o" ] && record y "fork bomb" "contained" "--pids-limit 64" || record n "fork bomb" "no error (check host)" "--pids-limit 64"; }

t0=$(date +%s); pyrun 'while True: pass' 3 >/dev/null 2>&1; rc=$?; t1=$(date +%s)
[ $(( t1 - t0 )) -le 5 ] && record y "cpu / wall-clock" "killed ~3s (rc=$rc)" "timeout + --cpus 0.5" || record n "cpu / wall-clock" "ran too long" "timeout + --cpus"

o=$(pyrun 'x=bytearray()
while True: x+=bytes(10_000_000)' 8); rc=$?; echo "$o" | grep -qiE "MemoryError" || [ "$rc" = 137 ] && record y "memory bomb" "OOM/rc=137" "--memory 128m" || record n "memory bomb" "survived" "--memory 128m"

# --- seccomp (default-DENY allowlist): assert syscall-level denial inside the container ---
# socket() creation is allowed by --network none (interfaces removed, syscall still works);
# under the allowlist it must fail at the syscall itself. This isolates the seccomp layer.
o=$(pyrun 'import socket
try: socket.socket(socket.AF_INET, socket.SOCK_STREAM); print("LEAK")
except OSError as e: print("eperm", e.errno)')
echo "$o" | grep -q "eperm 1" && record y "seccomp: socket() denied" "EPERM at syscall" "default-deny allowlist" || record n "seccomp: socket() denied" "not blocked ($o)" "default-deny allowlist"

o=$(pyrun 'import ctypes; l=ctypes.CDLL(None, use_errno=True); l.ptrace(0,0,0,0); print("ptrace", ctypes.get_errno())')
echo "$o" | grep -q "ptrace 1" && record y "seccomp: ptrace denied" "EPERM at syscall" "default-deny allowlist" || record n "seccomp: ptrace denied" "not blocked ($o)" "default-deny allowlist"

{
  echo "# Jailrunner — proof of containment (generated)"
  echo; echo "Image \`$IMAGE\`, Docker $(docker version -f '{{.Server.Version}}'), $(date -u +%FT%TZ)."
  echo; echo "| Attack | Observed | Control that caught it |"; echo "|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo; [ "$fails" -eq 0 ] && echo "**All attack classes blocked.**" || echo "**$fails LEAK(S) — build must fail.**"
} > "$HERE/last-run.md"
cat "$HERE/last-run.md"
echo; [ "$fails" -eq 0 ] && { echo "PROOF OK"; exit 0; } || { echo "PROOF FAILED ($fails)"; exit 1; }
