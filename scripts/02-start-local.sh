#!/usr/bin/env bash
# Downloads the Zeek pcap (once), builds the images and starts the laptop side.
source "$(dirname "$0")/lib.sh"
load_properties
[[ -f "$DOCKER_DIR/.env" ]] || die "docker/.env missing - run ./scripts/01-provision-cloud.sh first"

PCAP="$ROOT_DIR/data/pcaps/zeek_streamer.pcap"
if [[ ! -s "$PCAP" ]]; then
  info "downloading Zeek sample capture (~1 GB, one time) from ${PCAP_URL}"
  mkdir -p "$(dirname "$PCAP")"
  curl -fL --retry 3 -C - -o "$PCAP.part" "$PCAP_URL"
  mv "$PCAP.part" "$PCAP"
fi

info "building images"
compose build

info "starting containers (Elastic + Kibana take 1-2 minutes)"
compose up -d

info "waiting for SIEM setup (index templates, Kibana dashboard, Elasticsearch sink connector)"
compose wait siem-setup >/dev/null 2>&1 || true
compose logs --no-log-prefix siem-setup | grep -vE '^waiting' | tail -5

cat <<MSG

  Kibana dashboard : $KIBANA_URL
  Discover (SIEM)  : $DISCOVER_URL
  PII masking check: $PII_CHECK_URL
  Kafka Connect    : http://localhost:8083/connectors/siem-elasticsearch-sink/status
  Fluent Bit       : http://localhost:2020/api/v1/metrics
MSG

next_steps "check containers, the sink connector and Elastic doc counts (alerts arrive within 1-2 min)" \
           "./scripts/05-status.sh" \
           "open the Kibana dashboard" \
           "open \"$KIBANA_URL\""
