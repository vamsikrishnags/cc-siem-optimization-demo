#!/usr/bin/env bash
# Stops the laptop side and destroys every Confluent Cloud resource Terraform created for this DEMO_ID.
source "$(dirname "$0")/lib.sh"
load_properties
require DEMO_ID

info "stopping containers and removing volumes"
compose --profile tools down -v --remove-orphans || true

read -r -p "Destroy the Confluent Cloud resources of demo '$DEMO_ID' (siem-$DEMO_ID-*)? [y/N] " answer
[[ "$answer" =~ ^[Yy]$ ]] || { info "cloud resources kept"; exit 0; }

# Flink-registered schemas are not Terraform resources and live in the environment's Schema Registry,
# so delete them now - the Schema Registry API key used for this is destroyed with everything else.
if [[ -f "$DOCKER_DIR/.env" ]]; then
  read -r -p "Hard-delete the demo's Schema Registry subjects (zeek_*, syslog_events, siem_events, threat_intel, ...)?
  They belong to the environment: answer n if another demo still runs in the same environment. [Y/n] " answer
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
  info "DEMO_ID cleared - ./scripts/00-check-prereqs.sh will generate a new one"
fi
