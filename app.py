import os
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from waf_engine import WAFEngine
from rate_limiter import RateLimiter
from security_logger import SecurityLogger
from ai_threat_detector import detect_threats, adaptive_rules

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-production')

waf_engine = WAFEngine()
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
security_logger = SecurityLogger()


@app.before_request
def apply_rate_limiting():
    ip = request.remote_addr
    if not rate_limiter.is_allowed(client_id=ip):
        security_logger.log(f'Rate limit exceeded for IP: {ip}')
        return jsonify({'error': 'Too many requests'}), 429


@app.before_request
def waf_protect():
    ip = request.remote_addr
    security_logger.log(f'Incoming request from IP: {ip} to {request.path}')


@app.route('/waf/status', methods=['GET'])
def waf_status():
    return jsonify({'status': 'WAF is operational'}), 200


@app.route('/waf/analyze', methods=['POST'])
def waf_analyze():
    data = request.json
    if data is None:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    threats = waf_engine.analyze_request(data)

    ai_predictions = None
    try:
        import numpy as np
        payload_str = str(data)
        # Limit to first 1000 characters to avoid performance issues with large payloads
        sample = np.array([ord(c) for c in payload_str[:1000]], dtype=float)
        if len(sample) > 1:
            ai_predictions = detect_threats(sample).tolist()
    except Exception as exc:
        security_logger.log(f'AI detection error: {exc}')

    threat_detected = len(threats) > 0
    security_logger.log(
        f'Analysis complete - threats: {threats}, ai_predictions: {ai_predictions}'
    )

    return jsonify({
        'threat_detected': threat_detected,
        'threats': threats,
        'ai_predictions': ai_predictions,
    }), 200


@app.route('/waf/logs', methods=['GET'])
def waf_logs():
    log_file = os.getenv('LOG_FILE', 'security.log')
    logs = []
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = f.readlines()
    return jsonify({'logs': logs}), 200


@app.route('/waf/config', methods=['GET', 'POST'])
def waf_config():
    if request.method == 'POST':
        new_config = request.json
        return jsonify({'message': 'Config updated', 'config': new_config}), 200
    return jsonify({'config': 'Current configuration settings'}), 200


if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', 'False').lower() in ('1', 'true')
    port = int(os.getenv('PORT', 5000))
    app.run(debug=debug, host='0.0.0.0', port=port)