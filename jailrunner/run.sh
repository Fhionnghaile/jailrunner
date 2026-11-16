#!/usr/bin/env bash
# Run one untrusted file in a throwaway, hardened container.
#   ./jailrunner/run.sh path/to/code.py           (python)
#   echo 'print(1)' | ./jailrunner/run.sh -        (stdin)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(dirname "$HERE")"
export JR_source "$HERE/flags.sh"
IMAGE="${JR_IMAGE:-jailrunner}"

src="$(mktemp -d)"; trap 'rm -rf "$src"' EXIT
if [ "${1:-}" = "-" ] || [ -z "${1:-}" ]; then cat > "$src/main.py"; else cp "$1" "$src/main.py"; fi

mapfile -t FLAGS < <(jr_flags)
set +e
timeout --signal=KILL "$JR_WALL_CLOCK" \
  docker run "${FLAGS[@]}" \
    -v "$src:/work:ro" \
    "$IMAGE" python /work/main.py
rc=$?
set -e
[ "$rc" -eq 137 ] && echo "[jailrunner] killed at wall-clock/memory limit (rc=137)" >&2
exit "$rc"
