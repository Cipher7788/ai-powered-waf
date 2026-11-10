"""Verify that a fresh checkout starts and writes logs using its local configuration."""

import json
import os
from pathlib import Path
from shutil import copy2
import socket
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener


def test_fresh_checkout_starts_and_writes_logs(tmp_path):
    source = Path(__file__).resolve().parents[1]
    checkout = tmp_path / "fresh checkout"
    checkout.mkdir()
    for path in source.glob("*.py"):
        copy2(path, checkout / path.name)
    sample = (source / ".env.sample").read_text(encoding="utf-8")
    (checkout / ".env").write_text(
        sample.replace("replace-with-a-long-random-secret", "test-secret")
        .replace("replace-with-a-long-random-admin-token", "test-admin-token")
        .replace("LOG_FILE=security.log", "LOG_FILE=logs/security.log"),
        encoding="utf-8-sig",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    configured_keys = {
        line.split("=", 1)[0] for line in sample.splitlines()
        if line and not line.startswith("#")
    }
    configured_keys.add("PYTHON_DOTENV_DISABLED")
    env = {key: value for key, value in os.environ.items() if key not in configured_keys}
    env["PORT"] = str(port)

    base_url = f"http://127.0.0.1:{port}/waf"
    http = build_opener(ProxyHandler({}))
    output = tmp_path / "startup.log"
    with output.open("wb") as log:
        process = subprocess.Popen(
            [sys.executable, "main.py"], cwd=checkout, env=env,
            stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 15
            while process.poll() is None and time.monotonic() < deadline:
                try:
                    with http.open(f"{base_url}/status", timeout=1) as response:
                        assert json.load(response)["status"] == "WAF is operational"
                except (URLError, TimeoutError, ConnectionError):
                    time.sleep(0.1)
                else:
                    break
            else:
                raise AssertionError(output.read_text(encoding="utf-8", errors="replace"))

            request = Request(f"{base_url}/logs", headers={"X-Admin-Token": "test-admin-token"})
            with http.open(request, timeout=3) as response:
                assert any("/waf/status" in line for line in json.load(response)["logs"])
            assert (checkout / "logs" / "security.log").is_file()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
