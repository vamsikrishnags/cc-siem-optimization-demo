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
  warn "demo.properties missing"
  next_steps "create your inputs file, fill it in (README > Prerequisites), then re-run this check" \
             "cp demo.properties.example demo.properties && ./scripts/00-check-prereqs.sh"
  exit 1
fi
(( ok )) || die "fix the warnings above, then re-run: ./scripts/00-check-prereqs.sh"
info "prerequisites look good"

if [[ -z "${CC_SERVICE_ACCOUNT_ID:-}" || -z "${CC_CLOUD_API_KEY:-}" || -z "${CC_CLOUD_API_SECRET:-}" ]]; then
  next_steps "create the service account + Cloud API key (README > Prerequisites; suggested name siem-demo-$DEMO_ID-admin), fill CC_SERVICE_ACCOUNT_ID / CC_CLOUD_API_KEY / CC_CLOUD_API_SECRET, then provision" \
             "./scripts/01-provision-cloud.sh"
else
  next_steps "provision Confluent Cloud: environment, cluster, Flink, Tableflow (~10 min)" \
             "./scripts/01-provision-cloud.sh"
fi
