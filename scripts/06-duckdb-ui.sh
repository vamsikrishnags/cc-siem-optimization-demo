#!/usr/bin/env bash
# Opens the DuckDB UI (http://localhost:4213) on your Mac with the Tableflow Iceberg catalog attached
# and views zeek_conn, zeek_dns, zeek_http, syslog_events ready to query.
# Needs the DuckDB CLI >= 1.2.1 (curl https://install.duckdb.org | sh  or  brew install duckdb).
# Catalog tokens expire after ~30 minutes - just quit (.exit) and re-run.
#   ./scripts/06-duckdb-ui.sh                    # open the UI
#   ./scripts/06-duckdb-ui.sh "SELECT ..."        # run one query in the terminal instead
source "$(dirname "$0")/lib.sh"
[[ -f "$DOCKER_DIR/.env" ]] || die "docker/.env missing - run ./scripts/01-provision-cloud.sh first"
command -v duckdb >/dev/null || die "duckdb CLI not found - install: curl https://install.duckdb.org | sh"

set -a
# shellcheck disable=SC1091
source "$DOCKER_DIR/.env"
set +a
require TABLEFLOW_CATALOG_ENDPOINT TABLEFLOW_API_KEY TABLEFLOW_API_SECRET KAFKA_CLUSTER_ID DEMO_ID

# the init file contains the Tableflow secret: private temp file, removed on exit
INIT="$(mktemp "${TMPDIR:-/tmp}/siem-duckdb-init.XXXXXX")"
chmod 600 "$INIT"
trap '[[ -n "$INIT" && -f "$INIT" ]] && rm -f "$INIT"' EXIT

cat > "$INIT" <<SQL
INSTALL httpfs; LOAD httpfs;
INSTALL iceberg; LOAD iceberg;
INSTALL azure; LOAD azure;
SET azure_transport_option_type = 'curl';
CREATE SECRET tableflow (
  TYPE ICEBERG,
  CLIENT_ID '${TABLEFLOW_API_KEY}',
  CLIENT_SECRET '${TABLEFLOW_API_SECRET}',
  ENDPOINT '${TABLEFLOW_CATALOG_ENDPOINT}',
  OAUTH2_SCOPE 'catalog'
);
ATTACH 'warehouse' AS lake (TYPE iceberg, SECRET tableflow, ENDPOINT '${TABLEFLOW_CATALOG_ENDPOINT}');
-- short view names over the demo's Iceberg tables (<topic>_<DEMO_ID>)
CREATE VIEW zeek_conn     AS SELECT * FROM lake."${KAFKA_CLUSTER_ID}"."zeek_conn_${DEMO_ID}";
CREATE VIEW zeek_dns      AS SELECT * FROM lake."${KAFKA_CLUSTER_ID}"."zeek_dns_${DEMO_ID}";
CREATE VIEW zeek_http     AS SELECT * FROM lake."${KAFKA_CLUSTER_ID}"."zeek_http_${DEMO_ID}";
CREATE VIEW syslog_events AS SELECT * FROM lake."${KAFKA_CLUSTER_ID}"."syslog_events_${DEMO_ID}";
SQL

if [[ $# -gt 0 ]]; then            # ./scripts/06-duckdb-ui.sh "SELECT ..."  -> run one query, no UI
  duckdb -init "$INIT" -c "$*"
  exit
fi

info "DuckDB UI -> http://localhost:4213   (views: zeek_conn, zeek_dns, zeek_http, syslog_events)"
info "keep this terminal open; type .exit to stop"
duckdb -ui -init "$INIT" || true

next_steps "UI tokens expire after ~30 min: start a fresh session if queries return 401" \
           "./scripts/06-duckdb-ui.sh" \
           "when the demo is over: stop everything and destroy the cloud resources" \
           "./scripts/99-teardown.sh"
