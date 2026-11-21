# Jailrunner — a hardened runner for untrusted code — manual

*One page, eight blocks. Every figure here comes from this repository's own tests and README.*

## 1. Claim
Untrusted code runs in a throwaway container, and a fork bomb, outbound network, filesystem write, CPU spin and memory bomb are each shown to fail on a real run.

## 2. What it is
You hand Jailrunner some code you do not trust. It runs it inside a locked-down, single-use container and returns the output. Every escape route is blocked, and a test harness proves each block on every build.

## 3. Demo
Recorded terminal run of the containment proof: `docs/jailrunner-proof.cast` (play with `asciinema play docs/jailrunner-proof.cast`). Not hosted live on purpose: a public code runner is an attack surface.

## 4. Run it yourself
**Prerequisites:** Docker, make, bash.

```bash
docker build -t jailrunner .
make proof
bash tools/seccomp-selftest/run-selftest.sh
```

## 5. What you will see
Each attack in `proof/run.sh` reports as blocked, and the harness exits 0. If any attack gets through, the run fails (CI fails the build the same way). See `PROOF.md` for the attack table.

## 6. 30-second talking point
> Any product that runs code it did not write needs a wall it can trust. I built that wall and then tried to break it: five attack classes, each one shown failing on every build. The seccomp profile is an allowlist, so an unknown system call is refused rather than allowed.

## 7. Scope and limits
- Container isolation, not a VM or microVM. A kernel zero-day is out of scope (gVisor or Firecracker raise that bar).
- The seccomp allowlist is validated for a compute-only Python workload. Adding languages means re-running the self-test.
- The control API needs the Docker socket. That trust boundary is documented in `THREAT-MODEL.md`.

## 8. Links
[Repository](https://github.com/fhionnghaile/jailrunner) · [README](README.md)
