"""Flask API for the AI-powered WAF."""
import hmac
import os
from flask import Flask, jsonify, request
from dotenv import load_dotenv
from waf_engine import WAFEngine
from rate_limiter import RateLimiter
from security_logger import SecurityLogger
from ai_threat_detector import detect_threats, extract_features

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024
app.config["WAF_SETTINGS"] = {
    "rate_limit_max_requests": int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "100")),
    "rate_limit_window_seconds": int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60")),
    "enabled_rules": ["sql_injection", "xss", "path_traversal", "command_injection"],
}
secret_key = os.getenv("SECRET_KEY")
if secret_key:
    app.secret_key = secret_key

waf_engine = WAFEngine()
rate_limiter = RateLimiter(
    max_requests=app.config["WAF_SETTINGS"]["rate_limit_max_requests"],
    window_seconds=app.config["WAF_SETTINGS"]["rate_limit_window_seconds"],
)
security_logger = SecurityLogger()


def _admin_authorized():
    expected = os.getenv("WAF_ADMIN_TOKEN", "")
    supplied = request.headers.get("X-Admin-Token", "")
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    return bool(expected) and bool(supplied) and hmac.compare_digest(expected, supplied)


def _admin_required():
    if not os.getenv("WAF_ADMIN_TOKEN"):
        return jsonify({"error": "Admin access is not configured"}), 503
    if not _admin_authorized():
        return jsonify({"error": "Admin authentication required"}), 401
    return None


@app.before_request
def apply_rate_limiting():
    client_id = request.remote_addr or "unknown"
    if not rate_limiter.is_allowed(client_id=client_id):
        security_logger.log(f"Rate limit exceeded for client: {client_id}")
        return jsonify({"error": "Too many requests"}), 429


@app.before_request
def log_request_metadata():
    security_logger.log(f"Incoming {request.method} request from {request.remote_addr or 'unknown'} to {request.path}")


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "Request body too large", "max_bytes": app.config["MAX_CONTENT_LENGTH"]}), 413


@app.route("/waf/status", methods=["GET"])
def waf_status():
    return jsonify({"status": "WAF is operational"}), 200


@app.route("/waf/analyze", methods=["POST"])
def waf_analyze():
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    data = request.get_json(silent=True)
    if data is None or not isinstance(data, (dict, list, str, int, float, bool)):
        return jsonify({"error": "Invalid JSON payload"}), 400

    threats = [
        name for name in app.config["WAF_SETTINGS"]["enabled_rules"]
        if name in waf_engine.rules and waf_engine.rules[name](data)
    ]
    try:
        ai_predictions = detect_threats(data)
        ai_features = extract_features(data)
    except (TypeError, ValueError, OverflowError) as exc:
        security_logger.log(f"Advisory detector error: {type(exc).__name__}")
        ai_predictions, ai_features = None, None

    security_logger.log(f"Analysis complete - threat_detected={bool(threats)}, threats={threats}")
    return jsonify({
        "threat_detected": bool(threats),
        "threats": threats,
        "ai_predictions": ai_predictions,
        "ai_features": ai_features,
    }), 200


@app.route("/waf/logs", methods=["GET"])
def waf_logs():
    auth_error = _admin_required()
    if auth_error:
        return auth_error
    log_file = security_logger.log_file
    try:
        if not os.path.exists(log_file):
            return jsonify({"logs": []}), 200
        with open(log_file, "r", encoding="utf-8", errors="replace") as handle:
            logs = handle.readlines()[-500:]
        return jsonify({"logs": logs}), 200
    except OSError:
        return jsonify({"error": "Security logs are unavailable"}), 500


@app.route("/waf/config", methods=["GET", "POST"])
def waf_config():
    if request.method == "GET":
        return jsonify({"config": dict(app.config["WAF_SETTINGS"])}), 200

    auth_error = _admin_required()
    if auth_error:
        return auth_error
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
    new_config = request.get_json(silent=True)
    if not isinstance(new_config, dict) or not new_config:
        return jsonify({"error": "Configuration must be a non-empty JSON object"}), 400

    allowed = {"rate_limit_max_requests", "rate_limit_window_seconds", "enabled_rules"}
    unknown = set(new_config) - allowed
    if unknown:
        return jsonify({"error": "Unknown configuration keys", "keys": sorted(unknown)}), 400

    updated = dict(app.config["WAF_SETTINGS"])
    if "rate_limit_max_requests" in new_config:
        value = new_config["rate_limit_max_requests"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100000:
            return jsonify({"error": "rate_limit_max_requests must be an integer from 1 to 100000"}), 400
        updated["rate_limit_max_requests"] = value
    if "rate_limit_window_seconds" in new_config:
        value = new_config["rate_limit_window_seconds"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 86400:
            return jsonify({"error": "rate_limit_window_seconds must be an integer from 1 to 86400"}), 400
        updated["rate_limit_window_seconds"] = value
    if "enabled_rules" in new_config:
        value = new_config["enabled_rules"]
        valid_rules = set(waf_engine.rules)
        if not isinstance(value, list) or any(not isinstance(rule, str) or rule not in valid_rules for rule in value):
            return jsonify({"error": "enabled_rules must be a list of supported rule names"}), 400
        updated["enabled_rules"] = list(dict.fromkeys(value))

    try:
        rate_limiter.configure(
            max_requests=updated["rate_limit_max_requests"],
            window_seconds=updated["rate_limit_window_seconds"],
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    app.config["WAF_SETTINGS"] = updated
    security_logger.log("WAF configuration updated by authenticated administrator")
    return jsonify({"message": "Config updated", "config": updated}), 200


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "False").lower() in ("1", "true")
    port = int(os.getenv("PORT", "5000"))
    app.run(debug=debug, host="127.0.0.1", port=port)
