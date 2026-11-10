# AI-Powered WAF

A small Flask API demonstrating rule-based inspection for common web payload threats, bounded request rate limiting, and authenticated administration. This is a defensive demo, not a substitute for a production WAF, secure application design, or penetration testing.

## Features

- Detects common SQL injection, XSS, path traversal, and command-injection patterns in nested JSON values.
- Performs bounded HTML/URL decoding before matching.
- Enforces a request-body limit and per-process sliding-window rate limit.
- Protects log retrieval and configuration updates with constant-time administrator-token comparison.
- Validates configuration before applying it at runtime.
- Rotates file logs and avoids recording request bodies.
- Includes regression tests and a non-root Docker image.

Important: pattern matching is heuristic. False positives and bypasses are possible. Test against your own traffic before enforcing it in production. The advisory anomaly feature is not a trained ML model and does not block traffic by itself.

## Local setup

Install Git and Python 3.10 or newer. Run these commands from a terminal.

```text
git clone https://github.com/Cipher7788/ai-powered-waf.git
cd ai-powered-waf
```

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.sample .env
```

If Python is available as `python` instead of `py`, use `python -m venv .venv`. The commands call the virtual environment's Python directly and work without changing PowerShell's script execution policy.

### macOS and Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.sample .env
```

If your Linux distribution packages virtual environment support separately, install its Python venv package first.

### Configure and start

Edit `.env` and set distinct random values for `WAF_ADMIN_TOKEN` and `SECRET_KEY`. To generate each value, run `-c "import secrets; print(secrets.token_urlsafe(48))"` with the virtual environment's Python.

| Task | Windows PowerShell | macOS and Linux |
|---|---|---|
| Start locally | `.\.venv\Scripts\python.exe main.py` | `.venv/bin/python main.py` |
| Run the test suite | `.\.venv\Scripts\python.exe -m pytest -q` | `.venv/bin/python -m pytest -q` |

The development server listens at `http://127.0.0.1:5000` by default. Open `http://127.0.0.1:5000/waf/status` in your browser to verify startup. Stop the server with Ctrl+C. The development server is intended for local use.

The sample configuration is included in the repository. Security logs are generated at runtime. The anomaly score uses built-in heuristics and setup requires no external dataset or model weights.

## Docker

Use Docker Engine with Compose on Linux or Docker Desktop in Linux container mode on Windows and macOS. Set `SECRET_KEY` and `WAF_ADMIN_TOKEN` in `.env` before starting the service:

~~~bash
docker compose up --build -d
docker compose logs -f waf
docker compose down
~~~

The Compose configuration binds to loopback by default. Put a properly configured TLS reverse proxy in front if remote access is required.

Compose uses a named volume for security logs. Fresh volumes inherit the log directory ownership from the image. Existing volumes retain their current ownership and must be writable by the container's `waf` user.

## API

| Method | Endpoint | Purpose | Access |
|---|---|---|---|
| GET | /waf/status | Health/status | Public |
| POST | /waf/analyze | Inspect a JSON payload | Public |
| GET | /waf/config | Read active settings | Public |
| POST | /waf/config | Validate and apply settings | Admin token required |
| GET | /waf/logs | Read latest log entries | Admin token required |

Administrative requests use either X-Admin-Token: <token> or Authorization: Bearer <token>. If WAF_ADMIN_TOKEN is not configured, administrative endpoints fail closed with HTTP 503.

JSON request bodies may be up to 1 MiB and contain up to 64 nested objects or arrays. Excessive nesting returns HTTP 400.

Analyze a sample payload in a POSIX shell:

~~~bash
curl -sS http://127.0.0.1:5000/waf/analyze \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT * FROM users"}'
~~~

In Windows PowerShell, send the same request with:

```powershell
Invoke-RestMethod -Uri http://127.0.0.1:5000/waf/analyze -Method Post -ContentType application/json -Body '{"query":"SELECT * FROM users"}'
```

Update the rate limit (replace the placeholder with your actual token):

~~~bash
curl -sS -X POST http://127.0.0.1:5000/waf/config \
  -H 'Content-Type: application/json' \
  -H 'X-Admin-Token: YOUR_ADMIN_TOKEN' \
  -d '{"rate_limit_max_requests":200,"rate_limit_window_seconds":60}'
~~~

Supported configuration keys:
- rate_limit_max_requests: integer from 1 to 100000.
- rate_limit_window_seconds: integer from 1 to 86400.
- enabled_rules: list containing any of sql_injection, xss, path_traversal, command_injection.

## Operational limitations

- The in-memory rate limiter is per process and does not coordinate across replicas. Use a shared limiter such as Redis for reliable distributed rate limiting.
- Trust proxy headers only after explicitly configuring a trusted reverse proxy.
- The log/config admin token should be long, unique, and delivered only over TLS when accessed remotely.
- Security rules should be validated with a representative benign/malicious corpus; do not assume this project guarantees prevention of all attacks.
- Runtime configuration is in memory and resets on restart.
