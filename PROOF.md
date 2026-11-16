# Jailrunner — what it stops (real runs)

Captured on **Docker 29.9.3**. The containment flags are image-agnostic; this transcript used a
minimal base to exercise each control. Re-generate against the built image any time with
`JR_IMAGE=jailrunner proof/run.sh` (it also runs in CI and **fails the build on any leak**).

| Attack | What ran | Observed result | Control that caught it |
|---|---|---|---|
| Identity | read `/proc/self/status` | `Uid: 65534` (non-root), `CapEff: 0000000000000000`, `NoNewPrivs: 1` | `--user 65534` · `--cap-drop ALL` · `--security-opt no-new-privileges` |
| Fork bomb | recursive `c(){ c\|c& }` | capped — host unaffected | `--pids-limit 64` |
| Outbound network | connect `1.1.1.1:80` | `Network is unreachable` | `--network none` |
| Filesystem write | `echo pwned > /etc/shadow` and `> /x` | `Read-only file system` | `--read-only` |
| CPU / wall-clock | `while :; do :; done` | **killed at 3.0s** (rc 137) | host-side `timeout` + `--cpus 0.5` |
| Memory bomb | grow a buffer unbounded | **OOM-killed** (exit 137) | `--memory 128m` |
| Host isolation | `cat /etc/shadow` | reads the *container's* file, never the host's | mount namespace |

### Raw transcript (excerpt)
```
# identity
Uid:	65534	65534	65534	65534
CapEff:	0000000000000000
NoNewPrivs:	1
# outbound network  -> /dev/tcp/1.1.1.1/80: Network is unreachable
# filesystem write  -> /etc/shadow: Read-only file system
# cpu/wall-clock     -> host-timeout rc=137  elapsed=3.0s
# memory bomb        -> [exit:137]
```
