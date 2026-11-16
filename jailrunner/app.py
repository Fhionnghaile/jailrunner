#!/usr/bin/env python3
"""Thin control API: POST /run {"code": "..."} -> {stdout, stderr, exit, timed_out}."""
import os, subprocess, tempfile, shutil, json
from flask import Flask, request, jsonify

app = Flask(__name__)
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IMAGE = os.environ.get("JR_IMAGE", "jailrunner")
WALL = int(os.environ.get("JR_WALL_CLOCK", "5"))
FLAGS = [
    "--rm","--network","none","--read-only",
    "--pids-limit","64","--memory","128m","--memory-swap","128m","--cpus","0.5",
    "--cap-drop","ALL","--security-opt","no-new-privileges",
    "--security-opt",f"seccomp={ROOT}/seccomp.json",
    "--user","65534:65534","--tmpfs","/tmp:rw,size=16m,noexec,nosuid","--workdir","/work",
]

@app.post("/run")
def run():
    code = (request.get_json(force=True) or {}).get("code", "")
    if len(code) > 64_000:
        return jsonify(error="code too large"), 413
    src = tempfile.mkdtemp()
    try:
        with open(os.path.join(src, "main.py"), "w") as f:
            f.write(code)
        cmd = ["docker","run",*FLAGS,
               "-v",f"{src}:/work:ro",
               IMAGE,"python","/work/main.py"]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=WALL)
            return jsonify(stdout=p.stdout[-10000:], stderr=p.stderr[-10000:],
                           exit=p.returncode, timed_out=False)
        except subprocess.TimeoutExpired:
            subprocess.run(["bash","-c","docker ps -q --filter ancestor=%s | xargs -r docker kill" % IMAGE])
            return jsonify(stdout="", stderr="killed: wall-clock limit", exit=137, timed_out=True)
    finally:
        shutil.rmtree(src, ignore_errors=True)

@app.get("/healthz")
def health(): return "ok"

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
