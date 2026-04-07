# SecDevOps Security Monitoring Dashboard

A production-style security monitoring stack built to demonstrate DevSecOps
principles relevant to financial institution environments (PCI-DSS, SOC2).

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────┐
│ Flask Security  │────▶│  Prometheus  │────▶│   Grafana   │
│ API (:5001)     │     │   (:9090)    │     │   (:3000)   │
│  /metrics       │     └──────┬───────┘     └─────────────┘
│  /login         │            │
│  /events        │     ┌──────▼───────┐
└─────────────────┘     │ Alertmanager │
                        │   (:9093)    │
┌─────────────────┐     └─────────────┘
│  Node Exporter  │────▶  CPU, Memory,
│   (:9100)       │       Disk, Network
└─────────────────┘
```

## Stack

| Component | Purpose |
|---|---|
| Flask + prometheus_client | Security event generator & metrics endpoint |
| Prometheus | Time-series metrics collection (15s scrape) |
| Grafana | Real-time security dashboard (11 panels) |
| Alertmanager | Threshold-based alerting (PCI-DSS aligned) |
| Node Exporter | Host system metrics (CPU, memory, disk) |

## Security Metrics Tracked

| Metric | PromQL | PCI-DSS Relevance |
|---|---|---|
| Failed logins/min | `rate(flask_security_failed_logins_total[1m])*60` | Req 8.3.4 — brute-force detection |
| Locked accounts | `flask_security_locked_accounts_total` | Req 8.3.4 — lockout enforcement |
| Suspicious IP hits | `flask_security_suspicious_ip_hits_total` | Req 10.7 — threat monitoring |
| Active sessions | `flask_security_active_sessions_gauge` | Req 8.2.8 — session management |
| Request p95 latency | `histogram_quantile(0.95, ...)` | SLA/SLO visibility |

## Alert Rules (Alertmanager)

```yaml
BruteForceDetected:   > 50 failed logins in 5 min  → CRITICAL
AccountLockoutSpike:  > 5 accounts locked in 10 min → WARNING
SuspiciousIPActivity: > 20 hits from flagged IP      → CRITICAL
HighErrorRate:        > 60% requests returning 401   → WARNING
```

## Dashboard Panels

1. Failed Logins / min — colour threshold: green < 10 < yellow < 30 < red
2. Active Sessions — live gauge
3. Locked Accounts — cumulative counter
4. Suspicious IP Hits — known bad IP tracker
5. Failed Logins Over Time — breakdown by reason (wrong\_password, unknown\_user, account\_locked, expired\_token)
6. Suspicious IP Activity Over Time — per-IP time-series
7. HTTP Requests by Status Code — 200 vs 401 rate
8. System CPU Usage — Node Exporter integration
9. Failed Logins by Source IP — ranked table with colour thresholds
10. Memory Usage % — gauge panel
11. Request Duration p95 — latency SLO tracking

## Quick Start

**Prerequisites:** Docker, Docker Compose v2+, WSL2 (Ubuntu)

```bash
git clone https://github.com/YOUR_USERNAME/security-monitoring-dashboard
cd security-monitoring-dashboard
docker compose up --build -d
```

Wait ~30 seconds, then open:

| Service | URL | Credentials |
|---|---|---|
| Grafana | http://localhost:3000 | admin / secdevops123 |
| Prometheus | http://localhost:9090 | — |
| Flask API | http://localhost:5001/health | — |
| Alertmanager | http://localhost:9093 | — |

Import the dashboard:
```bash
# Auto-detect datasource UID and import
DS_UID=$(curl -s http://admin:secdevops123@localhost:3000/api/datasources \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['uid'])")

python3 -c "
import json
dash = json.load(open('grafana/secdevops-dashboard.json'))
for p in dash.get('panels', []):
    p['datasource'] = {'type': 'prometheus', 'uid': '$DS_UID'}
    for t in p.get('targets', []):
        t['datasource'] = {'type': 'prometheus', 'uid': '$DS_UID'}
payload = {'dashboard': dash, 'overwrite': True, 'folderId': 0}
open('import-payload.json','w').write(json.dumps(payload))
"
curl -s -X POST http://admin:secdevops123@localhost:3000/api/dashboards/import \
  -H 'Content-Type: application/json' \
  --data-binary @import-payload.json | python3 -m json.tool
```

## Project Structure

```
security-monitoring-dashboard/
├── docker-compose.yml
├── flask-api/
│   ├── app.py                  # Security event simulator + Prometheus metrics
│   ├── requirements.txt
│   └── Dockerfile
├── prometheus/
│   ├── prometheus.yml          # Scrape config (15s interval)
│   └── alert_rules.yml         # PCI-DSS aligned alert thresholds
├── alertmanager/
│   └── alertmanager.yml        # Routing: warning → default, critical → pagerduty
└── grafana/
    └── provisioning/
        └── datasources/
            └── prometheus.yml  # Auto-provisioned datasource
```

## Skills Demonstrated

- **Docker Compose** — multi-service orchestration (5 containers)
- **Prometheus** — metrics scraping, PromQL queries, alert rules
- **Grafana** — dashboard-as-code via JSON, provisioning
- **Python / Flask** — instrumented API with `prometheus_client`
- **SecDevOps** — PCI-DSS aligned alerting, threat monitoring, brute-force detection
- **Infrastructure as Code** — all config in version-controlled YAML/JSON

## Related Projects

- [`devops-demo-api`](../devops-demo-api) — CI/CD pipeline with GitHub Actions
- [`terraform-aws-infra`](../terraform-aws-infra) — AWS infrastructure as code

## Author

Faisal Khandoker — Information Systems Security, Concordia University
