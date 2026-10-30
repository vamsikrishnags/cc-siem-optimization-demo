#!/usr/bin/env bash
# Prints the ad-hoc demo queries (flink/adhoc/demo_queries.sql) with this demo's table names
# (`syslog_raw` -> `syslog_raw_<DEMO_ID>`), ready to paste into a Confluent Cloud Flink SQL workspace.
#   ./scripts/07-flink-sql.sh                         # demo queries
#   ./scripts/07-flink-sql.sh flink/dml/11_siem_dns.sql   # any other SQL file
source "$(dirname "$0")/lib.sh"
load_properties
require DEMO_ID
suffix_tables < "${1:-$ROOT_DIR/flink/adhoc/demo_queries.sql}"

next_steps "paste the queries above into a Flink SQL workspace (catalog = demo environment, database = siem-demo-$DEMO_ID cluster), then open Kibana" \
           "open \"$KIBANA_URL\""
