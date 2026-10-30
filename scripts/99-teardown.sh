#!/usr/bin/env bash
# Stops the laptop side and destroys every Confluent Cloud resource Terraform created for this DEMO_ID.
source "$(dirname "$0")/lib.sh"
load_properties
require DEMO_ID

# DuckDB UI (scripts/06-duckdb-ui.sh) runs natively on the Mac, not in Docker. Match on its init-file
# name so only the demo's DuckDB is stopped, never another DuckDB session you have open.
if pgrep -f "siem-duckdb-init" >/dev/null 2>&1; then
  info "stopping the DuckDB UI (http://localhost:4213)"
  pkill -f "siem-duckdb-init" || true
fi
# leftover init files (they contain the Tableflow secret) if a session was ever killed hard
find "${TMPDIR:-/tmp}" -maxdepth 1 -name 'siem-duckdb-init.*' -type f -delete 2>/dev/null || true

info "stopping containers and removing volumes"
compose --profile tools down -v --remove-orphans || true

read -r -p "Destroy the Confluent Cloud resources of demo '$DEMO_ID' (siem-$DEMO_ID-*)? [y/N] " answer
if [[ ! "$answer" =~ ^[Yy]$ ]]; then
  info "cloud resources kept (still billed)"
  next_steps "restart the laptop side against the same cloud setup" \
             "./scripts/02-start-local.sh" \
             "or destroy the cloud resources later" \
             "./scripts/99-teardown.sh"
  exit 0
fi

# Flink-registered schemas are not Terraform resources and live in the environment's Schema Registry,
# so delete them now - the Schema Registry API key used for this is destroyed with everything else.
if [[ -f "$DOCKER_DIR/.env" ]]; then
  read -r -p "Hard-delete this demo's Schema Registry subjects (zeek_conn_${DEMO_ID}-value, siem_events_${DEMO_ID}-value, ...)? [Y/n] " answer
  if [[ ! "$answer" =~ ^[Nn]$ ]]; then
    ( set -a; source "$DOCKER_DIR/.env"; set +a; python3 "$ROOT_DIR/scripts/delete_schemas.py" ) \
      || warn "schema cleanup failed - see: python3 scripts/delete_schemas.py --print-cli <env-id>"
  fi
else
  warn "docker/.env not found - skipping schema cleanup (python3 scripts/delete_schemas.py --print-cli <env-id>)"
fi

# same inputs as provisioning
eval "$(sed -n '/^export_tf_vars() {/,/^}/p' "$(dirname "$0")/01-provision-cloud.sh")"
export_tf_vars
terraform -chdir="$TF_DIR" destroy -input=false
rm -f "$DOCKER_DIR/.env"
info "teardown complete"

read -r -p "Clear DEMO_ID in $(basename "$PROPS") so the next run creates a fresh setup with a new id? [y/N] " answer
if [[ "$answer" =~ ^[Yy]$ ]]; then
  python3 - "$PROPS" <<'PY'
import re, sys
path = sys.argv[1]
text = open(path).read()
open(path, "w").write(re.sub(r"^DEMO_ID=.*$", "DEMO_ID=", text, count=1, flags=re.M))
PY
  info "DEMO_ID cleared"
  next_steps "fresh run: generate a new demo id and check prerequisites" \
             "./scripts/00-check-prereqs.sh"
else
  next_steps "run again with the same demo id ($DEMO_ID)" \
             "./scripts/01-provision-cloud.sh"
fi
info "kept on purpose: your bootstrap service account and its API keys (delete them in the Confluent Cloud console when no longer needed)"
