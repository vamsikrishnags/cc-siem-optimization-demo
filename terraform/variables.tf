# Values are supplied by scripts/01-provision-cloud.sh from demo.properties (TF_VAR_*).

variable "demo_id" {
  description = "Unique suffix added to every resource name so all demo resources can be found later."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.demo_id))
    error_message = "demo_id must be 3-12 lowercase letters/digits."
  }
}

variable "cc_service_account_id" {
  description = "Bootstrap service account (sa-xxxxx) that owns the Cloud API key."
  type        = string
}

variable "cc_cloud_api_key" {
  type      = string
  sensitive = true
}

variable "cc_cloud_api_secret" {
  type      = string
  sensitive = true
}

variable "cc_environment_id" {
  description = "Existing environment id. Empty = create a new environment."
  type        = string
  default     = ""
}

variable "cc_environment_name" {
  description = "Base name of a new environment; the demo id is appended."
  type        = string
  default     = "siem-demo"
}

variable "cc_cloud" {
  description = "Cloud provider for the cluster and Flink pool: AWS, AZURE or GCP."
  type        = string
  default     = "AWS"

  validation {
    condition     = contains(["AWS", "AZURE", "GCP"], var.cc_cloud)
    error_message = "cc_cloud must be AWS, AZURE or GCP."
  }
}

variable "cc_region" {
  description = "Region for the Kafka cluster and Flink pool (e.g. us-east-2, eastus, us-central1)."
  type        = string
  default     = "us-east-2"
}

variable "cc_cluster_name" {
  description = "Base name of the Standard cluster; the demo id is appended."
  type        = string
  default     = "siem-demo"
}

variable "cc_flink_max_cfu" {
  type    = number
  default = 10
}

variable "tableflow_api_key" {
  description = "Optional pre-created Tableflow API key (owned by the service account). Empty = Terraform creates one."
  type        = string
  default     = ""
}

variable "tableflow_api_secret" {
  type      = string
  sensitive = true
  default   = ""
}

variable "pii_hash_salt" {
  type      = string
  sensitive = true
  default   = "change-me-demo-salt"
}
