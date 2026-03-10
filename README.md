# AI-Powered WAF

## Overview
The AI-Powered WAF is a web application firewall that uses Python/Flask and machine learning (Isolation Forest via scikit-learn) to detect and block common web threats such as SQL injection, XSS, path traversal, and command injection.

## Tech Stack
- **Backend**: Python 3.9+ / Flask
- **AI/ML**: scikit-learn (Isolation Forest), NumPy
- **Configuration**: python-dotenv
- **Logging**: Python standard library `logging`

## Architecture
```
┌──────────────┐       ┌──────────────────┐       ┌──────────────────────┐
│  HTTP Client │──────▶│  Flask App (app.py)│──────▶│  WAFEngine           │
└──────────────┘       │  - Rate limiting   │       │  - SQL Injection      │
                       │  - Request logging │       │  - XSS               │
                       └──────────────────┘       │  - Path Traversal    │
                                │                  │  - Command Injection  │
                                ▼                  └──────────────────────┘
                       ┌──────────────────┐               │
                       │  SecurityLogger  │               ▼
                       └──────────────────┘  ┌──────────────────────────┐
                                             │  AiThreatDetector        │
                                             │  (Isolation Forest)      │
                                             └──────────────────────────┘
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Cipher7788/ai-powered-waf.git
   cd ai-powered-waf
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**:
   ```bash
   cp .env.sample .env
   # Edit .env and set SECRET_KEY and other values
   ```

## Running the Application

```bash
python main.py
```

The server starts on `http://0.0.0.0:5000` by default.

## Running Tests

```bash
pytest tests/ -v
```

## Docker Deployment

> **Important**: Before deploying, set `SECRET_KEY` to a strong random value in your environment or shell. Never use the placeholder value in production.

```bash
export SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Build and start
docker-compose up --build

# Stop
docker-compose down
```

## API Documentation

Base URL: `http://localhost:5000`

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/waf/status` | Check WAF operational status |
| `POST` | `/waf/analyze` | Analyze a JSON payload for threats |
| `GET` | `/waf/logs` | Retrieve security log entries |
| `GET` | `/waf/config` | Get current WAF configuration |
| `POST` | `/waf/config` | Update WAF configuration |

### Example: Analyze a Request

```bash
curl -X POST http://localhost:5000/waf/analyze \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users"}'
```

**Response**:
```json
{
  "threat_detected": true,
  "threats": ["sql_injection"],
  "ai_predictions": [-1, 1, -1, ...]
}
```

### Rate Limiting

Requests are limited to **100 per 60-second window** per server instance. Exceeding this returns HTTP 429.

## Project Details
- **License**: MIT
- **Contributors**: Cipher7788
- **Version**: 1.0.0