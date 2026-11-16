# The confined image untrusted code runs inside. Minimal, no shell tools needed at runtime.
FROM python:3.12-slim
# No package installs, no extra tooling = smaller attack surface.
# Code is bind-mounted read-only at /work by the runner; nothing is baked in.
USER 65534:65534
WORKDIR /work
ENTRYPOINT ["python"]
