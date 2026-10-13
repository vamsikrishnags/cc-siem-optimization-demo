#!/usr/bin/env bash
# Checks local tooling and Docker resources.
source "$(dirname "$0")/lib.sh"

ok=1
for tool in terraform docker python3 curl; do
  if command -v "$tool" >/dev/null; then info "$tool: $(command -v "$tool")"; else warn "$tool not found"; ok=0; fi
done
docker compose version >/dev/null 2>&1 || { warn "docker compose v2 plugin not found"; ok=0; }

if docker info >/dev/null 2>&1; then
  mem=$(docker info --format '{{.MemTotal}}')
  gb=$(( mem / 1024 / 1024 / 1024 ))
  info "Docker memory: ${gb} GiB, arch: $(docker info --format '{{.Architecture}}')"
  (( gb >= 5 )) || warn "Give Docker at least 5-6 GiB (Docker Desktop > Settings > Resources); the stack uses ~4.5 GiB"
else
  warn "Docker daemon not reachable"; ok=0
fi

if [[ -f "$PROPS" ]]; then
  info "found $(basename "$PROPS")"
  load_properties
  ensure_demo_id
  env_desc="${CC_ENVIRONMENT_NAME:-siem-demo}-$DEMO_ID (new)"
  [[ -n "${CC_ENVIRONMENT_ID:-}" ]] && env_desc="$CC_ENVIRONMENT_ID (existing)"
  info "DEMO_ID=$DEMO_ID -> environment $env_desc, cluster ${CC_CLUSTER_NAME:-siem-demo}-$DEMO_ID, resources siem-$DEMO_ID-*"
  info "suggested bootstrap service account name: siem-demo-$DEMO_ID-admin"
else
  warn "demo.properties missing (cp demo.properties.example demo.properties)"; ok=0
fi
(( ok )) && info "prerequisites look good" || die "fix the warnings above"
