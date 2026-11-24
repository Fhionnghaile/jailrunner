# Jailrunner — a hardened runner for untrusted code

<!-- at-a-glance -->
> **Executes untrusted code in a throwaway container that is *proven* to contain it.**  
> **Result:** Self-asserting proof harness: read-only root, blocked egress, CPU/mem/pid caps, and a default-deny seccomp allowlist — each failure demonstrated on a real run.  
> **Reproduce:** `make proof   # + bash tools/seccomp-selftest/run-selftest.sh`  
> ![CI](https://github.com/fhionnghaile/jailrunner/actions/workflows/ci.yml/badge.svg) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Fhionnghaile/jailrunner/badge)](https://scorecard.dev/viewer/?uri=github.com/Fhionnghaile/jailrunner)
>
> **What this is worth:** Lets a product safely run code it doesn't trust — the core of any autograder, sandbox or plugin system — without betting the host on it.


Give it arbitrary code; it runs inside a throwaway, locked-down container and hands back
stdout/stderr/exit — while a **fork bomb, outbound network, filesystem write, CPU spin and memory
bomb all die at the wall.** The blocks are proven, not promised: see [PROOF.md](PROOF.md), re-run
any time with `proof/run.sh` (it runs in CI and fails the build on a leak).

## Demo
A recorded run of the containment proof: [`docs/jailrunner-proof.cast`](docs/jailrunner-proof.cast) — play with `asciinema play docs/jailrunner-proof.cast`, or upload to asciinema.org for an embeddable link. (Chosen over a live public runner — safer than hosting arbitrary code execution.)

## One-command run
```bash
docker build -t jailrunner .
echo 'print("hello from the cage")' | ./jailrunner/run.sh -
# or the control API:
docker compose up        # POST http://127.0.0.1:8080/run  {"code":"print(1)"}
```

## The containment set (one place: `jailrunner/flags.sh`)
`--network none` · `--read-only` + `--tmpfs` · `--pids-limit` · `--memory` · `--cpus` ·
`--cap-drop ALL` · `--security-opt no-new-privileges` · `--security-opt seccomp=seccomp.json` ·
`--user 65534` · host-side wall-clock `timeout`. Every flag maps to a row in
[THREAT-MODEL.md](THREAT-MODEL.md).

## Prove it
```bash
JR_IMAGE=jailrunner proof/run.sh   # runs every attack, asserts each is blocked
```

## License
MIT.

## Key decisions

- Default-deny seccomp allowlist over a blocklist: a blocklist fails open on the next unknown syscall; an allowlist fails closed.
- Hardening applied to per-run throwaway containers; the one trust boundary (the Docker socket on the control API) is documented, not hidden.
- Containment proven by a self-asserting harness that fails the build if any attack class gets through — not asserted in prose.

## Scope & limits

- Container isolation, not a VM/microVM — a kernel 0-day is out of scope (gVisor/Firecracker raise that bar).
- The seccomp allowlist is validated for a compute Python workload; widening the language set means re-running the self-test.

