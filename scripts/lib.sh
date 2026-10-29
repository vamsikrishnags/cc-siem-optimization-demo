#!/usr/bin/env bash
# Shared helpers: load demo.properties and fail fast on missing inputs.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROPS="${DEMO_PROPERTIES:-$ROOT_DIR/demo.properties}"
TF_DIR="$ROOT_DIR/terraform"
DOCKER_DIR="$ROOT_DIR/docker"

info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

load_properties() {
  [[ -f "$PROPS" ]] || die "$PROPS not found - copy demo.properties.example to demo.properties and fill it in"
  set -a
  # shellcheck disable=SC1090
  source "$PROPS"
  set +a
}

# Generates DEMO_ID once and persists it in demo.properties; every resource name carries it.
ensure_demo_id() {
  if [[ -z "${DEMO_ID:-}" ]]; then
    DEMO_ID="$(python3 -c 'import secrets, string; print("".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(6)))')"
    python3 - "$PROPS" "$DEMO_ID" <<'PY'
import re, sys
path, demo_id = sys.argv[1], sys.argv[2]
text = open(path).read()
if re.search(r"^DEMO_ID=.*$", text, flags=re.M):
    text = re.sub(r"^DEMO_ID=.*$", f"DEMO_ID={demo_id}", text, count=1, flags=re.M)
else:
    text = f"DEMO_ID={demo_id}\n" + text
open(path, "w").write(text)
PY
    info "generated DEMO_ID=$DEMO_ID (saved in $(basename "$PROPS"))"
  fi
  [[ "$DEMO_ID" =~ ^[a-z0-9]{3,12}$ ]] || die "DEMO_ID must be 3-12 lowercase letters/digits (got '$DEMO_ID')"
  export DEMO_ID
}

require() {
  local missing=()
  for name in "$@"; do [[ -n "${!name:-}" ]] || missing+=("$name"); done
  (( ${#missing[@]} == 0 )) || die "missing values in $(basename "$PROPS"): ${missing[*]}"
}

compose() { docker compose --project-directory "$DOCKER_DIR" -f "$DOCKER_DIR/docker-compose.yml" "$@"; }

# Prints copy-pasteable next steps (run from the repo root):
#   next_steps "what it does" "command" ["what it does" "command" ...]
next_steps() {
  printf '\n\033[1;32m==> Next step%s\033[0m   (run from %s)\n' "$( (( $# > 2 )) && echo s)" "$ROOT_DIR"
  while (( $# >= 2 )); do
    printf '  \033[2m# %s\033[0m\n  %s\n\n' "$1" "$2"
    shift 2
  done
}

KIBANA_URL="http://localhost:5601/app/dashboards#/view/siem-optimization"
