# SecDevOps Security Monitoring Dashboard

A production-style security monitoring stack built to demonstrate DevSecOps principles
aligned with financial institution compliance requirements (PCI-DSS, SOC2).

**Author:** Khandoker Faisal — Information Systems Security, Concordia University
**Stack:** Flask · Prometheus · Grafana · Alertmanager · Node Exporter · Docker Compose

---

## Table of Contents

1. [What This Project Does](#what-this-project-does)
2. [Architecture Overview](#architecture-overview)
3. [How the System Works — Stage by Stage](#how-the-system-works--stage-by-stage)
   - [Stage 1 — Flask generates security events](#stage-1--flask-generates-security-events)
   - [Stage 2 — Prometheus collects and stores metrics](#stage-2--prometheus-collects-and-stores-metrics)
   - [Stage 3 — Grafana visualizes the data](#stage-3--grafana-visualizes-the-data)
   - [Stage 4 — Alertmanager fires on thresholds](#stage-4--alertmanager-fires-on-thresholds)
   - [Stage 5 — Node Exporter adds host metrics](#stage-5--node-exporter-adds-host-metrics)
4. [Security Metrics & PCI-DSS Alignment](#security-metrics--pci-dss-alignment)
5. [What is PCI-DSS?](#what-is-pci-dss)
6. [Dashboard Panels](#dashboard-panels)
7. [Quick Start](#quick-start)
8. [Production Changes Guide](#production-changes-guide)
   - [Add a new metric](#1-add-a-new-metric)
   - [Add a new Grafana panel](#2-add-a-new-grafana-panel)
   - [Change the data source](#3-change-the-data-source)
   - [Connect real log sources](#4-connect-real-log-sources)
   - [Enable real Slack or PagerDuty alerts](#5-enable-real-slack-or-pagerduty-alerts)
   - [Change scrape interval](#6-change-scrape-interval)
   - [Add a new alert rule](#7-add-a-new-alert-rule)
9. [Project Structure](#project-structure)
10. [Skills Demonstrated](#skills-demonstrated)
11. [Related Projects](#related-projects)

---

## What This Project Does

This dashboard simulates the security monitoring layer of a financial institution's
SecDevOps pipeline. It tracks authentication anomalies, brute-force patterns, account
lockouts, and suspicious IP activity — all in real time — with alert rules aligned to
PCI-DSS requirements.

In a production bank environment, this stack would replace the simulated Flask event
generator with real log shippers (Filebeat, Fluentd) feeding from actual application
servers, SIEM systems, and WAFs.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     Docker Compose Network                       │
│                                                                  │
│  ┌─────────────────┐   scrape     ┌──────────────────┐          │
│  │  Flask Security │─────/metrics─▶│   Prometheus     │          │
│  │  API  (:5001)   │              │   (:9090)        │          │
│  │                 │              │                  │          │
│  │  /metrics       │              │  PromQL engine   │          │
│  │  /login         │              │  Alert rules     │          │
│  │  /health        │              │  Time-series DB  │          │
│  │  /events        │              └──────┬───────────┘          │
│  └─────────────────┘                    │                       │
│                                    query│        send alerts     │
│  ┌─────────────────┐              ┌─────▼──────┐  ┌──────────┐  │
│  │  Node Exporter  │─────metrics──▶  Grafana   │  │  Alert-  │  │
│  │  (:9100)        │              │  (:3000)   │  │  manager │  │
│  │                 │              │            │  │  (:9093) │  │
│  │  CPU, memory    │              │  11 panels │  │          │  │
│  │  disk, network  │              │  10s refresh│  │  Slack / │  │
│  └─────────────────┘              └────────────┘  │  PagerDuty│ │
│                                                   └──────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## How the System Works — Stage by Stage

### Stage 1 — Flask generates security events

```
[Background thread]
      │
      ├── random.choice(FAKE_IPS)         ← picks a source IP
      ├── random.choice(USERS)            ← picks a username
      │
      ├── 70% chance → FAILED LOGIN
      │     └── failed_logins_total.inc() ← Prometheus counter goes up
      │         ├── reason: wrong_password
      │         ├── reason: unknown_user
      │         ├── reason: account_locked
      │         └── reason: expired_token
      │
      ├── 30% chance → SUCCESSFUL LOGIN
      │     └── active_sessions.inc()     ← Gauge goes up
      │         └── (thread sleeps 5-30s, then dec())
      │
      ├── IP in BAD_IPS? → suspicious_ip_hits_total.inc()
      │
      └── fail_count[ip] >= 5? → locked_accounts_total.inc()

[HTTP endpoint /metrics]
      │
      └── Prometheus scrapes this every 15 seconds
          Returns all counters in text/plain format:
          flask_security_failed_logins_total{reason="wrong_password",source_ip="45.33.32.156"} 42
          flask_security_active_sessions_gauge 2
          flask_security_locked_accounts_total 127
```

**Key file:** `flask-api/app.py`

The `prometheus_client` library handles the `/metrics` endpoint automatically.
You define a counter with `Counter('name', 'help', ['label1', 'label2'])` and
call `.inc()` when the event happens. That's it — Prometheus handles the rest.

---

### Stage 2 — Prometheus collects and stores metrics

```
Every 15 seconds:
┌─────────────────────────────────────────────────────┐
│  Prometheus scrape cycle                             │
│                                                      │
│  GET http://flask-api:5000/metrics                   │
│       └── parses text → stores as time-series       │
│                                                      │
│  GET http://node-exporter:9100/metrics               │
│       └── parses text → stores as time-series       │
│                                                      │
│  Evaluates alert_rules.yml every 15s:                │
│       increase(failed_logins[5m]) > 50?              │
│       └── YES for 1 min → send to Alertmanager      │
└─────────────────────────────────────────────────────┘

PromQL examples used in this project:

  rate(flask_security_failed_logins_total[1m]) * 60
    → converts cumulative counter to "logins failing per minute"

  sum by (reason) (rate(flask_security_failed_logins_total[2m]) * 60)
    → groups by attack type: wrong_password, unknown_user, etc.

  increase(flask_security_failed_logins_total[5m])
    → total new failures in the last 5 minutes (used in alert rules)

  histogram_quantile(0.95, rate(flask_security_request_duration_seconds_bucket[5m]))
    → 95th percentile latency (p95 SLO)

  1 - avg(rate(node_cpu_seconds_total{mode='idle'}[2m]))
    → CPU usage percentage from Node Exporter
```

**Key file:** `prometheus/prometheus.yml` (scrape config), `prometheus/alert_rules.yml`

---

### Stage 3 — Grafana visualizes the data

```
Browser opens http://localhost:3000
         │
         ▼
  Grafana dashboard loads (refresh every 10s)
         │
         ├── Panel: "Failed Logins / min"
         │     └── PromQL: rate(flask_security_failed_logins_total[1m]) * 60
         │         Threshold: green < 10 < yellow < 30 < red (background colour)
         │
         ├── Panel: "Failed Logins Over Time (by reason)"
         │     └── PromQL: sum by (reason)(rate(...[2m]) * 60)
         │         Shows 4 lines: wrong_password, unknown_user, account_locked, expired_token
         │
         ├── Panel: "Suspicious IP Activity"
         │     └── PromQL: sum by (ip)(rate(flask_security_suspicious_ip_hits_total[2m]))
         │         Red line per flagged IP
         │
         └── Panel: "Failed Logins by Source IP (table)"
               └── PromQL: sort_desc(sum by (source_ip)(increase(...[30m])))
                   Heatmap colours: green < 5 < yellow < 20 < red
```

**Key file:** `grafana/provisioning/datasources/prometheus.yml` (auto-wires the datasource)

---

### Stage 4 — Alertmanager fires on thresholds

```
Prometheus evaluates rules every 15 seconds:

  Rule: BruteForceDetected
    expr:  increase(flask_security_failed_logins_total[5m]) > 50
    for:   1m          ← must stay true for 1 full minute before firing
    label: severity=critical
         │
         ▼
  Alertmanager receives the alert
         │
         ├── severity=critical → route: 'critical-alerts'
         │     └── → PagerDuty / Slack #security-critical
         │
         └── severity=warning  → route: 'default'
               └── → Slack #security-alerts

  Active alert rules in this project:
  ┌──────────────────────────┬────────────────────────────────┬──────────┐
  │ Alert                    │ Condition                      │ Severity │
  ├──────────────────────────┼────────────────────────────────┼──────────┤
  │ BruteForceDetected       │ >50 failed logins in 5 min     │ critical │
  │ SuspiciousIPActivity     │ >20 hits from flagged IP in 5m │ critical │
  │ AccountLockoutSpike      │ >5 accounts locked in 10 min   │ warning  │
  │ HighErrorRate            │ >60% requests returning 401    │ warning  │
  └──────────────────────────┴────────────────────────────────┴──────────┘
```

**Key file:** `prometheus/alert_rules.yml`, `alertmanager/alertmanager.yml`

---

### Stage 5 — Node Exporter adds host metrics

```
Node Exporter container
   │  (mounts host /proc and /sys read-only)
   │
   ├── node_cpu_seconds_total{mode="idle"}
   │     └── Grafana: 1 - avg(rate(...[2m])) = CPU usage %
   │
   ├── node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes
   │     └── Grafana: 1 - (available/total) = Memory usage %
   │
   └── node_disk_io_time_seconds_total
         └── Available for disk I/O panels (extend as needed)
```

**Key file:** `docker-compose.yml` (node-exporter service)

---

## Security Metrics & PCI-DSS Alignment

| Metric | PromQL Query | PCI-DSS Requirement |
|---|---|---|
| Failed logins/min | `rate(flask_security_failed_logins_total[1m])*60` | **8.3.4** — limit repeated access attempts |
| Locked accounts | `flask_security_locked_accounts_total` | **8.3.4** — lockout after N failures |
| Suspicious IP hits | `flask_security_suspicious_ip_hits_total` | **10.7** — detect/report security failures |
| Active sessions | `flask_security_active_sessions_gauge` | **8.2.8** — idle session timeout |
| 401 error rate | `rate(http_requests_total{status_code="401"}[5m])` | **10.2.1** — log invalid access attempts |
| Request p95 latency | `histogram_quantile(0.95, rate(...bucket[5m]))` | **6.4** — protect public-facing applications |

---

## What is PCI-DSS?

**PCI-DSS** stands for **Payment Card Industry Data Security Standard**. It is a set of
security requirements created by major credit card companies (Visa, Mastercard, Amex,
Discover) to protect cardholder data.

Any organization that stores, processes, or transmits credit card data — including banks
like Scotiabank — must comply with PCI-DSS. Non-compliance can result in fines of up to
$100,000/month and loss of the ability to process card payments.

### The 12 PCI-DSS Requirements (high level)

```
1.  Install and maintain network security controls (firewalls)
2.  Apply secure configurations to all system components
3.  Protect stored account data (encryption)
4.  Protect cardholder data in transit (TLS)
5.  Protect all systems against malware (antivirus)
6.  Develop and maintain secure systems and software
7.  Restrict access to system components by business need
8.  Identify users and authenticate access ← THIS PROJECT
9.  Restrict physical access to cardholder data
10. Log and monitor all access to system components ← THIS PROJECT
11. Test security of systems and networks regularly
12. Support information security with organizational policies
```

### How this project maps to PCI-DSS

**Requirement 8.3.4** — "Invalid authentication attempts are limited by locking out the
user ID after not more than 10 attempts within 30 minutes."

This project implements:
- Counter tracking per-username failed attempts (`failed_logins_total`)
- Lockout counter when threshold crossed (`locked_accounts_total`)
- Alert firing when 50+ failures detected in 5 minutes (`BruteForceDetected`)

**Requirement 10.2.1** — "Audit logs capture all individual user access to cardholder data
and all invalid logical access attempts."

This project implements:
- HTTP 401 response tracking (`http_requests_total{status_code="401"}`)
- Source IP attribution on every failed login event
- Time-series retention for forensic investigation

**Requirement 10.7** — "Failures of critical security controls are detected, reported, and
responded to promptly."

This project implements:
- Suspicious IP alerting within 1 minute of threshold crossing
- Alertmanager routing to on-call (PagerDuty/Slack stub)

---

## Dashboard Panels

| # | Panel | Type | What it shows |
|---|---|---|---|
| 1 | Failed Logins / min | Stat | Real-time rate, red at 30+ |
| 2 | Active Sessions | Stat | Live session count |
| 3 | Locked Accounts (total) | Stat | Cumulative lockouts |
| 4 | Suspicious IP Hits (total) | Stat | Known bad IP counter |
| 5 | Failed Logins Over Time (by reason) | Time-series | 4 attack vectors over time |
| 6 | Suspicious IP Activity Over Time | Time-series | Per-IP activity graph |
| 7 | HTTP Requests by Status Code | Time-series | 200 vs 401 rate |
| 8 | System CPU Usage | Time-series | Node Exporter — host CPU |
| 9 | Failed Logins by Source IP | Table | Ranked by volume, colour coded |
| 10 | Memory Usage % | Gauge | RAM utilisation |
| 11 | Request Duration p95 | Stat | 95th percentile latency |

---

## Quick Start

**Prerequisites:** Docker, Docker Compose v2+, WSL2 (Ubuntu) or Linux

```bash
# 1. Clone the repo
git clone https://github.com/fa1829/security-monitoring-dashboard.git
cd security-monitoring-dashboard

# 2. Start all 5 containers
docker compose up --build -d

# 3. Verify all containers are running
docker compose ps

# 4. Test the Flask API
curl http://localhost:5001/health
```

Open the services:

| Service | URL | Credentials |
|---|---|---|
| Grafana dashboard | http://localhost:3000 | admin / secdevops123 |
| Prometheus | http://localhost:9090 | — |
| Flask security API | http://localhost:5001/health | — |
| Alertmanager | http://localhost:9093 | — |

Import the Grafana dashboard:

```bash
# Auto-detect datasource UID and build import payload
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

Stop the stack:

```bash
docker compose down
```

---

## Production Changes Guide

This section explains exactly what to change and where when adapting this project
for a real production environment.

---

### 1. Add a new metric

**Scenario:** You want to track password reset attempts as a new security signal.

**Step 1 — Define the metric in `flask-api/app.py`:**

```python
# Add near the other Counter definitions (around line 15)
password_resets = Counter(
    'flask_security_password_reset_attempts_total',
    'Password reset attempts',
    ['username', 'source_ip', 'status']   # labels let you filter in PromQL
)
```

**Step 2 — Increment it when the event occurs:**

```python
# Inside your route or simulator
password_resets.labels(
    username=user,
    source_ip=ip,
    status='initiated'   # or 'completed', 'failed', 'expired'
).inc()
```

**Step 3 — Rebuild the Flask container:**

```bash
docker compose up --build flask-api -d
```

**Step 4 — Verify Prometheus is receiving it:**

```bash
curl -s "http://localhost:9090/api/v1/query?\
query=flask_security_password_reset_attempts_total" | python3 -m json.tool
```

**Step 5 — Add a Grafana panel** (see next section).

---

### 2. Add a new Grafana panel

**Scenario:** Show the password reset metric as a time-series panel.

**Option A — Via Grafana UI (easiest):**

1. Open http://localhost:3000 → your dashboard → click **Edit**
2. Click **Add** → **Visualization**
3. In the query box, enter:
   ```
   sum by (status) (rate(flask_security_password_reset_attempts_total[2m]) * 60)
   ```
4. Set visualization type to **Time series**
5. Set title: `Password Reset Attempts / min`
6. Click **Save dashboard**

**Option B — Via dashboard JSON (reproducible, recommended for production):**

Export the dashboard: Dashboards → your dashboard → Share → Export → Save to file.
Add the panel JSON block to the `panels` array and re-import.

---

### 3. Change the data source

**Scenario:** You want to connect to a remote Prometheus instance instead of the local container.

**Step 1 — Edit `grafana/provisioning/datasources/prometheus.yml`:**

```yaml
# Change this:
url: http://prometheus:9090

# To your remote Prometheus address:
url: http://your-prometheus-server.internal:9090

# If your Prometheus requires authentication, add:
basicAuth: true
basicAuthUser: your_username
secureJsonData:
  basicAuthPassword: your_password
```

**Step 2 — Restart Grafana to reload provisioning:**

```bash
docker compose restart grafana
```

**Step 3 — Verify the datasource:**

```bash
curl -s http://admin:secdevops123@localhost:3000/api/datasources \
  | python3 -m json.tool
```

**For AWS Managed Prometheus (AMP):**

```yaml
url: https://aps-workspaces.ca-central-1.amazonaws.com/workspaces/YOUR_WORKSPACE_ID
jsonData:
  sigV4Auth: true
  sigV4Region: ca-central-1
  sigV4AuthType: default
```

---

### 4. Connect real log sources

**Scenario:** Replace the Flask event simulator with real application logs.

**Current (simulated):**
```
Flask background thread → Prometheus counters → /metrics
```

**Production pattern:**
```
Real app logs → Filebeat/Fluentd → Logstash → Elasticsearch
                                             → Prometheus Pushgateway → Prometheus
```

**Step 1 — Add Filebeat to `docker-compose.yml`:**

```yaml
filebeat:
  image: docker.elastic.co/beats/filebeat:8.12.0
  volumes:
    - ./filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml
    - /var/log/auth.log:/var/log/auth.log:ro   # Linux SSH auth log
    - /var/log/nginx:/var/log/nginx:ro          # Nginx access logs
  restart: unless-stopped
```

**Step 2 — Create `filebeat/filebeat.yml`:**

```yaml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/auth.log
    fields:
      log_type: ssh_auth

output.logstash:
  hosts: ["logstash:5044"]
```

**Step 3 — Add SSH failed login pattern to your metric parser:**

```python
# Parse sshd failed password lines:
# "Failed password for invalid user admin from 45.33.32.156 port 54321 ssh2"
import re
SSH_FAIL_PATTERN = re.compile(
    r'Failed password for (?:invalid user )?(\S+) from (\S+)'
)
```

---

### 5. Enable real Slack or PagerDuty alerts

**Scenario:** When `BruteForceDetected` fires, notify the security team on Slack.

**Step 1 — Get your Slack webhook URL:**
Slack → Apps → Incoming Webhooks → Add to Workspace → copy the URL.

**Step 2 — Edit `alertmanager/alertmanager.yml`:**

```yaml
receivers:
  - name: 'default'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#security-alerts'
        title: 'SecDevOps Alert — {{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
        send_resolved: true

  - name: 'critical-alerts'
    pagerduty_configs:
      - routing_key: 'YOUR_PAGERDUTY_INTEGRATION_KEY'
        description: '{{ .GroupLabels.alertname }}: {{ .CommonAnnotations.summary }}'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#security-critical'
```

**Step 3 — Restart Alertmanager:**

```bash
docker compose restart alertmanager
```

**Step 4 — Test the alert manually:**

```bash
curl -X POST http://localhost:9093/api/v2/alerts \
  -H 'Content-Type: application/json' \
  -d '[{"labels":{"alertname":"BruteForceDetected","severity":"critical"},
       "annotations":{"summary":"Test alert"}}]'
```

---

### 6. Change scrape interval

**Scenario:** Your production environment needs metrics every 5 seconds instead of 15.

**Edit `prometheus/prometheus.yml`:**

```yaml
global:
  scrape_interval: 5s       # was 15s
  evaluation_interval: 5s   # was 15s — also affects alert rule checks

# Or override per job only:
scrape_configs:
  - job_name: flask-security-api
    scrape_interval: 5s     # override just this job
    static_configs:
      - targets: ['flask-api:5000']
```

**Restart Prometheus:**

```bash
docker compose restart prometheus
```

**Note:** Shorter intervals increase storage usage and CPU load. For production, 15–30s
is standard. Use 5s only for SLO-critical services.

---

### 7. Add a new alert rule

**Scenario:** Alert when active sessions drop to zero (possible service outage).

**Edit `prometheus/alert_rules.yml` — add under the existing rules:**

```yaml
      - alert: NoActiveSessions
        expr: flask_security_active_sessions_gauge == 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "No active sessions for 2 minutes"
          description: >
            The active session gauge has been zero for 2 minutes.
            The authentication service may be down.
```

**Reload Prometheus rules without restart:**

```bash
curl -X POST http://localhost:9090/-/reload
```

**Verify the rule loaded:**

```bash
curl -s http://localhost:9090/api/v1/rules | python3 -m json.tool | grep "NoActiveSessions"
```

---

## Project Structure

```
security-monitoring-dashboard/
├── docker-compose.yml              # Orchestrates all 5 containers
├── setup.sh                        # One-shot launcher script
├── .gitignore
├── README.md
│
├── flask-api/
│   ├── app.py                      # Security event simulator + all Prometheus metrics
│   ├── requirements.txt            # flask, prometheus_client
│   └── Dockerfile                  # python:3.11-slim base image
│
├── prometheus/
│   ├── prometheus.yml              # Scrape config — which targets, how often
│   └── alert_rules.yml             # PCI-DSS aligned alert thresholds
│
├── alertmanager/
│   └── alertmanager.yml            # Alert routing: warning → default, critical → pagerduty
│
└── grafana/
    ├── secdevops-dashboard.json     # Exportable dashboard (11 panels)
    └── provisioning/
        └── datasources/
            └── prometheus.yml      # Auto-provisions Prometheus datasource on startup
```

---

## Skills Demonstrated

| Skill | Evidence |
|---|---|
| Docker Compose | 5-container orchestration with shared network, volumes, env vars |
| Prometheus | Scrape config, PromQL queries, alert rule evaluation |
| Grafana | Dashboard-as-code via JSON, datasource provisioning |
| Python / Flask | Instrumented API with `prometheus_client`, background threads |
| SecDevOps | PCI-DSS Req 8.3.4 and 10.7 aligned alerting and monitoring |
| Infrastructure as Code | All configuration in version-controlled YAML/JSON |
| Linux / WSL | Deployed and debugged on Ubuntu via WSL2 |
| Git | Conventional commits, .gitignore, remote push workflow |

---

## Related Projects

- [`devops-demo-api`](../devops-demo-api) — CI/CD pipeline with GitHub Actions
- [`terraform-aws-infra`](../terraform-aws-infra) — AWS infrastructure as code (VPC, EC2, S3)

---

## Author

**Khandoker Faisal**
Information Systems Security — Concordia University, Montreal
GitHub: [fa1829](https://github.com/fa1829)
