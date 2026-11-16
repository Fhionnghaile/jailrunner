# Jailrunner — seccomp hardening & test report

## What changed

The old `seccomp.json` was **allow-by-default** (`SCMP_ACT_ALLOW`) with a blocklist of ~38
dangerous syscalls — the same shape as Docker's stock profile. It was replaced with a
**default-DENY allowlist**: `defaultAction: SCMP_ACT_ERRNO` (EPERM), permitting only the
**122 syscalls** an untrusted *compute* Python workload actually needs. Everything else —
network sockets, `ptrace`/`process_vm_*`, `mount` and namespace creation, module loading,
`bpf`/`perf_event_open`, `keyctl`, time-setting, swap, reboot, and the **entire 32-bit
ABI** — now returns EPERM.

This is strictly stronger: a blocklist fails open (a new dangerous syscall you didn't list is
allowed); an allowlist fails closed (anything unforeseen is denied).

## How the allowlist was built

1. **Empirical floor** — `strace -f` of the interpreter starting and running a representative
   submission (arithmetic, `json`/`re`/`heapq`/`collections`, threads, file reads) → 41 syscalls.
2. **Vetted superset** — added the syscalls arbitrary stdlib compute can need (io-multiplexing
   for `asyncio`/`selectors`, `time.sleep`, file management in the writable tmpfs, sqlite,
   compression, subprocess) — each deliberate, none from the denied set.
3. Network, debugging, mount/namespace, module, and privilege syscalls were **deliberately
   excluded**. The 32-bit ABI is excluded by pinning `architectures` to `SCMP_ARCH_X86_64`
   only, which closes the classic i386-syscall seccomp bypass.

## How it was tested (reproducible, no Docker needed)

`tools/seccomp-selftest/run-selftest.sh` compiles the **same allow set** into a seccomp-BPF
filter — exactly what the container runtime compiles `seccomp.json` down to — installs it with
`PR_SET_NO_NEW_PRIVS` + `SECCOMP_MODE_FILTER`, then `execve()`s Python under it. Results:

| # | Test | Result |
|---|---|---|
| 1 | Representative compute (threads, json, regex, heapq, file read) | ✅ runs clean |
| 2 | stdlib + tempfile + sqlite + gzip/bz2/lzma + hashlib + **subprocess** | ✅ runs clean (child stays caged) |
| 3 | `socket()` — network at the syscall layer | ✅ **EPERM** |
| 4 | `ptrace(PTRACE_TRACEME)` | ✅ **EPERM** |
| 5 | `mount()` / `unshare(CLONE_NEWUSER)` | ✅ **EPERM** |

Test 2 matters most: it's the case that catches an allowlist cut too tight. An early version
*did* break `tempfile` (missing `unlink`/`mkdir`/`rename`); the self-test caught it, and the
file-management group was added and re-verified. That's the whole point of testing sufficiency,
not just denial.

## Confirm it on the real Docker runner (the end-to-end check)

The self-test above validates the filter semantics without Docker. To confirm end-to-end on the
actual runner image, on a host with Docker:

```bash
cd jailrunner
make proof      # builds the image and runs proof/run.sh against the hardened container
```

`proof/run.sh` now also asserts the seccomp layer directly (socket + ptrace denied inside the
container), alongside the existing network/filesystem/fork/cpu/memory containment checks. A
green `make proof` plus a green `tools/seccomp-selftest/run-selftest.sh` is the full picture.

## If a legitimate submission ever hits EPERM

Run it under the self-test harness; the failing syscall will surface. If it's a genuine
compute need (not network/privilege), add it to `allowlist.txt`, regenerate, and re-run the
self-test. Keep the denied families denied.
