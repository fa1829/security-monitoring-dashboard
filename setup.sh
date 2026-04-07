#!/bin/bash
# Run this from inside ~/security-monitoring-dashboard
set -e
echo "==> Checking Docker..."
docker --version
docker compose version

echo "==> Building and starting all services..."
docker compose up --build -d

echo ""
echo "All services starting. Give it 30 seconds, then open:"
echo "  Grafana      → http://localhost:3000  (admin / secdevops123)"
echo "  Prometheus   → http://localhost:9090"
echo "  Flask API    → http://localhost:5000/health"
echo "  Alertmanager → http://localhost:9093"
