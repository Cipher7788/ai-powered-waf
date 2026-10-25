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

## Requirements and local setup

Python 3.10+ is recommended.

~~~bash
git clone https://github.com/Cipher7788/ai-powered-waf.git
cd ai-powered-waf
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.sample .env
~~~

Set a long random WAF_ADMIN_TOKEN and SECRET_KEY in .env. Generate strong values locally with:

~~~bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
~~~

Run the local development server:

~~~bash
python main.py
~~~

It binds to 127.0.0.1:5000 for local development. Do not expose Flask's development server to the internet.

## Tests

~~~bash
pytest -q
~~~

## Docker

After setting SECRET_KEY and WAF_ADMIN_TOKEN in .env:

~~~bash
docker compose up --build -d
docker compose logs -f waf
docker compose down
~~~

The Compose configuration binds to loopback by default. Put a properly configured TLS reverse proxy in front if remote access is required.

## API

| Method | Endpoint | Purpose | Access |
|---|---|---|---|
| GET | /waf/status | Health/status | Public |
| POST | /waf/analyze | Inspect a JSON payload | Public |
| GET | /waf/config | Read active settings | Public |
| POST | /waf/config | Validate and apply settings | Admin token required |
| GET | /waf/logs | Read latest log entries | Admin token required |

Administrative requests use either X-Admin-Token: <token> or Authorization: Bearer <token>. If WAF_ADMIN_TOKEN is not configured, administrative endpoints fail closed with HTTP 503.

Analyze a sample payload:

~~~bash
curl -sS http://127.0.0.1:5000/waf/analyze \
  -H 'Content-Type: application/json' \
  -d '{"query":"SELECT * FROM users"}'
~~~

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

- The in-memory rate limiter is per process and does not coordinate across Gunicorn workers or replicas. Use a shared limiter such as Redis for reliable distributed rate limiting.
- Trust proxy headers only after explicitly configuring a trusted reverse proxy.
- The log/config admin token should be long, unique, and delivered only over TLS when accessed remotely.
- Security rules should be validated with a representative benign/malicious corpus; do not assume this project guarantees prevention of all attacks.
- Runtime configuration is in memory and resets on restart.
