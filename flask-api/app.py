from flask import Flask, jsonify, request
from prometheus_client import Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
import random, time, threading

app = Flask(__name__)

# ── Prometheus metrics ──────────────────────────────────────────
failed_logins = Counter(
    'flask_security_failed_logins_total',
    'Failed login attempts',
    ['username', 'source_ip', 'reason']
)
successful_logins = Counter(
    'flask_security_successful_logins_total',
    'Successful logins',
    ['username']
)
active_sessions = Gauge(
    'flask_security_active_sessions_gauge',
    'Currently active sessions'
)
locked_accounts = Counter(
    'flask_security_locked_accounts_total',
    'Accounts locked after brute-force'
)
suspicious_ips = Counter(
    'flask_security_suspicious_ip_hits_total',
    'Hits from suspicious IPs',
    ['ip', 'endpoint']
)
http_requests = Counter(
    'flask_security_http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status_code']
)
request_duration = Histogram(
    'flask_security_request_duration_seconds',
    'Request duration',
    ['endpoint']
)

# ── Fake data pools ─────────────────────────────────────────────
USERS    = ['admin', 'faisal', 'root', 'john.doe', 'svc_account']
FAKE_IPS = ['192.168.1.10', '10.0.0.5', '203.0.113.42',
            '198.51.100.7', '172.16.0.3', '45.33.32.156']
BAD_IPS  = ['45.33.32.156', '198.51.100.7']
REASONS  = ['wrong_password', 'unknown_user',
            'account_locked', 'expired_token']

# ── Background event simulator ──────────────────────────────────
def simulate_events():
    fail_count = {}
    while True:
        ip   = random.choice(FAKE_IPS)
        user = random.choice(USERS)
        if random.random() < 0.70:
            reason = random.choice(REASONS)
            failed_logins.labels(username=user, source_ip=ip, reason=reason).inc()
            fail_count[ip] = fail_count.get(ip, 0) + 1
            if fail_count[ip] >= 5:
                locked_accounts.inc()
                fail_count[ip] = 0
        else:
            successful_logins.labels(username=user).inc()
            active_sessions.inc()
            def end_session():
                time.sleep(random.randint(5, 30))
                active_sessions.dec()
            threading.Thread(target=end_session, daemon=True).start()
        if ip in BAD_IPS:
            suspicious_ips.labels(ip=ip, endpoint='/login').inc()
        time.sleep(random.uniform(0.5, 2.0))

# ── Routes ──────────────────────────────────────────────────────
@app.route('/metrics')
def metrics():
    http_requests.labels(method='GET', endpoint='/metrics', status_code='200').inc()
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

@app.route('/health')
def health():
    return jsonify(status='ok', service='flask-security-api')

@app.route('/login', methods=['POST'])
def login():
    start = time.time()
    ip   = request.remote_addr
    data = request.get_json(silent=True) or {}
    user = data.get('username', 'unknown')
    if random.random() < 0.3:
        successful_logins.labels(username=user).inc()
        status, code = 'success', 200
    else:
        reason = random.choice(REASONS)
        failed_logins.labels(username=user, source_ip=ip, reason=reason).inc()
        status, code = 'unauthorized', 401
    request_duration.labels(endpoint='/login').observe(time.time() - start)
    http_requests.labels(method='POST', endpoint='/login', status_code=str(code)).inc()
    return jsonify(status=status), code

@app.route('/events')
def events():
    return jsonify(
        active_sessions=active_sessions._value.get(),
        service='flask-security-api'
    )

if __name__ == '__main__':
    threading.Thread(target=simulate_events, daemon=True).start()
    app.run(host='0.0.0.0', port=5000)
