#!/usr/bin/env bash
# Live demo: publish a new threat-intel indicator; Flink starts flagging matching events within seconds.
#   ./scripts/04-add-threat-indicator.sh [indicator] [ip|domain] [category] [severity] [name]
source "$(dirname "$0")/lib.sh"
INDICATOR="${1:-198.51.100.200}"
TYPE="${2:-ip}"
CATEGORY="${3:-scanner}"
SEVERITY="${4:-high}"
NAME="${5:-Mass port scanner (analyst-added, live demo)}"
compose run --rm --no-deps reference-loader \
  python reference_loader.py add-indicator "$INDICATOR" "$TYPE" "$CATEGORY" "$SEVERITY" "$NAME"
info "added $INDICATOR - watch Kibana for rule 'Threat intel match: $CATEGORY'"
