#!/usr/bin/env bash
# Quick health view of the laptop side.
source "$(dirname "$0")/lib.sh"
compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
echo
curl -fs localhost:8083/connectors/siem-elasticsearch-sink/status 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("sink connector:", d["connector"]["state"], [t["state"] for t in d["tasks"]])' \
  || warn "Kafka Connect not reachable"
for idx in siem_events pipeline_metrics; do
  n=$(curl -fs "localhost:9200/$idx/_count" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])' || echo "n/a")
  echo "elasticsearch $idx: $n docs"
done
