# Jailrunner — threat model

**Asset:** the host (and other tenants) must survive arbitrary, hostile code.

| Threat | Control | Evidence |
|--------|---------|----------|
| Exhaust processes (fork bomb) | `--pids-limit 64` | PROOF.md |
| Exfiltrate / call home | `--network none` | PROOF.md (connect fails) |
| Write/modify the host or image | `--read-only` + `--tmpfs noexec,nosuid` | PROOF.md |
| Burn CPU forever | host `timeout` + `--cpus 0.5` | PROOF.md (killed ~3s) |
| Exhaust memory | `--memory 128m` (swap capped) | PROOF.md (OOM 137) |
| Gain privileges | `--cap-drop ALL` + `--security-opt no-new-privileges` + non-root `--user` | PROOF.md (CapEff=0) |
| Dangerous syscalls (mount, ptrace, bpf, keyctl, settime…) | `seccomp.json` (errno) layered under cap-drop | seccomp.json |
| Escape the mount view | mount namespace (default) | PROOF.md (own /etc) |

**Control-plane trust boundary:** the API container mounts the Docker socket to spawn runners —
so the **API process is privileged** and must never execute untrusted input itself; it only
*launches* confined runners. Isolate the API host; don't co-locate it with other trust domains.
**Not covered:** kernel 0-days (use gVisor/Kata for a second boundary), and side-channels.
