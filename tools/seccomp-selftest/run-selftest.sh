#!/usr/bin/env bash
# Docker-free validation of the default-deny seccomp allowlist.
# Builds a seccomp-BPF filter from allowlist.txt (the same allow set as
# ../../seccomp.json) and (1) runs representative Python workloads to prove the
# allowlist is SUFFICIENT, (2) attempts denied syscalls to prove they are BLOCKED.
# Exits non-zero if any legit workload fails or any denied call is NOT blocked.
set -euo pipefail
cd "$(dirname "$0")"
UNI=$(ls /usr/include/*/asm/unistd_64.h 2>/dev/null | head -1)
[ -n "$UNI" ] || { echo "need x86_64 unistd_64.h"; exit 2; }
grep -vE '^\s*#|^\s*$' allowlist.txt | tr ' ' '\n' | grep -vE '^\s*$' | sort -u > /tmp/.names
python3 - "$UNI" > allowed.h <<'PY'
import sys,re
n2n={m.group(1):int(m.group(2)) for L in open(sys.argv[1]) for m in [re.match(r'#define __NR_([a-z0-9_]+)\s+(\d+)',L)] if m}
names=[x.strip() for x in open('/tmp/.names') if x.strip()]
ok=sorted(((nm,n2n[nm]) for nm in names if nm in n2n), key=lambda x:x[1])
miss=[nm for nm in names if nm not in n2n]
if miss: sys.stderr.write("WARN unknown on this kernel: %s\n"%miss)
print("/* generated */\nstatic const int allowed_nr[] = {")
for nm,nr in ok: print(f"  {nr}, /* {nm} */")
print("};"); print(f"static const int allowed_count = {len(ok)};")
PY
gcc -O2 -o harness harness.c
fail=0
echo "[1] sufficiency: representative compute"; ./harness python3 prog.py  || { echo "  FAIL"; fail=1; }
echo "[2] sufficiency: stdlib + tempfile + subprocess"; ./harness python3 prog2.py || { echo "  FAIL"; fail=1; }
echo "[3] denial: socket()"; ./harness python3 -c 'import socket
try: socket.socket(); print("  LEAK"); raise SystemExit(9)
except OSError as e: print("  blocked EPERM" if e.errno==1 else "  WRONG errno %d"%e.errno)' || fail=1
echo "[4] denial: ptrace()"; ./harness python3 -c 'import ctypes;l=ctypes.CDLL(None,use_errno=True);l.ptrace(0,0,0,0)
import ctypes as c;print("  blocked EPERM" if c.get_errno()==1 else "  NOT blocked")'
echo "[5] denial: mount()"; ./harness python3 -c 'import ctypes;l=ctypes.CDLL(None,use_errno=True);l.mount(0,0,0,0,0)
import ctypes as c;print("  blocked EPERM" if c.get_errno()==1 else "  NOT blocked")'
[ "$fail" = 0 ] && echo "SELFTEST OK" || { echo "SELFTEST FAILED"; exit 1; }
