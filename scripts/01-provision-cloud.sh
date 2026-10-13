#!/usr/bin/env bash
# Provisions Confluent Cloud with Terraform - environment, Standard cluster, Schema Registry,
# Flink compute pool + statements, raw topics, and Tableflow (Confluent-managed storage) -
# then writes docker/.env for the laptop containers.
#
#   AUTO_APPROVE=1 ./scripts/01-provision-cloud.sh     # skip the terraform confirmation prompt
source "$(dirname "$0")/lib.sh"
load_properties
ensure_demo_id
require CC_SERVICE_ACCOUNT_ID CC_CLOUD_API_KEY CC_CLOUD_API_SECRET CC_CLOUD CC_REGION

export_tf_vars() {
  export TF_VAR_demo_id="$DEMO_ID"
  export TF_VAR_cc_service_account_id="$CC_SERVICE_ACCOUNT_ID"
  export TF_VAR_cc_cloud_api_key="$CC_CLOUD_API_KEY"
  export TF_VAR_cc_cloud_api_secret="$CC_CLOUD_API_SECRET"
  export TF_VAR_cc_environment_id="${CC_ENVIRONMENT_ID:-}"
  export TF_VAR_cc_environment_name="${CC_ENVIRONMENT_NAME:-siem-demo}"
  export TF_VAR_cc_cloud="$(printf '%s' "$CC_CLOUD" | tr '[:lower:]' '[:upper:]')"
  export TF_VAR_cc_region="$CC_REGION"
  export TF_VAR_cc_cluster_name="${CC_CLUSTER_NAME:-siem-demo}"
  export TF_VAR_cc_flink_max_cfu="${CC_FLINK_MAX_CFU:-10}"
  export TF_VAR_tableflow_api_key="${TABLEFLOW_API_KEY:-}"
  export TF_VAR_tableflow_api_secret="${TABLEFLOW_API_SECRET:-}"
  export TF_VAR_pii_hash_salt="${PII_HASH_SALT:-change-me-demo-salt}"
}
export_tf_vars

# a plain string (not an array): macOS bash 3.2 treats an empty array as unbound under `set -u`
APPROVE_FLAG=""
[[ "${AUTO_APPROVE:-0}" == "1" ]] && APPROVE_FLAG="-auto-approve"

info "demo id: $DEMO_ID"
info "terraform init"
terraform -chdir="$TF_DIR" init -upgrade -input=false >/dev/null

info "terraform apply (Confluent Cloud) - takes ~10 minutes"
# shellcheck disable=SC2086
terraform -chdir="$TF_DIR" apply -input=false $APPROVE_FLAG

info "writing docker/.env from terraform outputs"
terraform -chdir="$TF_DIR" output -json | python3 "$ROOT_DIR/scripts/write_env.py" "$DOCKER_DIR/.env"
chmod 600 "$DOCKER_DIR/.env"
info "done - next: ./scripts/02-start-local.sh"
