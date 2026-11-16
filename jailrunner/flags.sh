# The Jailrunner hardening set — sourced by run.sh and proof/run.sh.
# Every flag maps to a threat in THREAT-MODEL.md. Change here, change everywhere.
JR_WALL_CLOCK="${JR_WALL_CLOCK:-5}"      # seconds, enforced host-side
JR_SECCOMP="${JR_SECCOMP:-$PWD/seccomp.json}"   # HOST path to the seccomp profile
jr_flags() {
  printf '%s\n' \
    --rm --network none --read-only \
    --pids-limit 64 --memory 128m --memory-swap 128m --cpus 0.5 \
    --cap-drop ALL --security-opt no-new-privileges \
    --security-opt "seccomp=${JR_SECCOMP:-$PWD/seccomp.json}" \
    --user 65534:65534 \
    --tmpfs /tmp:rw,size=16m,noexec,nosuid \
    --workdir /work
}
