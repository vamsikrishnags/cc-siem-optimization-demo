#!/usr/bin/env bash
# Queries the Tableflow Iceberg tables (Confluent-managed storage) with DuckDB via the Iceberg REST catalog.
#   ./scripts/03-lake-query.sh                       # canned demo queries
#   ./scripts/03-lake-query.sh "SELECT COUNT(*) FROM syslog_events"
source "$(dirname "$0")/lib.sh"
compose --profile tools run --rm lake-query python lake_query.py "$@"

next_steps "explore the same Iceberg tables in the DuckDB browser UI (http://localhost:4213)" \
           "./scripts/06-duckdb-ui.sh" \
           "live demo: add a threat-intel indicator and watch Kibana flag it" \
           "./scripts/04-add-threat-indicator.sh" \
           "when the demo is over: stop everything and destroy the cloud resources" \
           "./scripts/99-teardown.sh"
