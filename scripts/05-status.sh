#!/usr/bin/env bash
# Quick health view of the laptop side.
source "$(dirname "$0")/lib.sh"
compose ps --format 'table {{.Service}}\t{{.State}}\t{{.Status}}'
echo
curl -fs localhost:8083/connectors/siem-elasticsearch-sink/status 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("sink connector:", d["connector"]["state"], [t["state"] for t in d["tasks"]])' \
  || warn "Kafka Connect not reachable"
siem_docs=0
for idx in siem_events pipeline_metrics; do
  n=$(curl -fs "localhost:9200/$idx/_count" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])' || echo "n/a")
  echo "elasticsearch $idx: $n docs"
  [[ "$idx" == "siem_events" && "$n" =~ ^[0-9]+$ ]] && siem_docs=$n
done

if (( siem_docs > 0 )); then
  next_steps "open the Kibana dashboard" \
             "open \"$KIBANA_URL\"" \
             "after ~10-15 min (first Tableflow snapshot): query the full-fidelity Iceberg lake" \
             "./scripts/03-lake-query.sh"
else
  next_steps "no SIEM events yet: wait 1-2 minutes and check again" \
             "./scripts/05-status.sh" \
             "still empty? look at the shipper and connector logs (also check the Flink statements in the Confluent Cloud console)" \
             "docker compose --project-directory docker logs --tail 50 fluent-bit connect"
fi
