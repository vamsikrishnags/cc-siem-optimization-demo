#!/usr/bin/env bash
# Queries the Tableflow Iceberg tables (Confluent-managed storage) with DuckDB via the Iceberg REST catalog.
#   ./scripts/03-lake-query.sh                       # canned demo queries
#   ./scripts/03-lake-query.sh "SELECT COUNT(*) FROM syslog_events"
source "$(dirname "$0")/lib.sh"
compose --profile tools run --rm lake-query python lake_query.py "$@"
