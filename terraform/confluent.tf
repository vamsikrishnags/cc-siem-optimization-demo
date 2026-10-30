# ---------------------------------------------------------------------------
# Environment, Standard cluster, Schema Registry and API keys.
# Every API key is owned by the bootstrap service account from demo.properties,
# so the demo never needs to create additional service accounts.
# ---------------------------------------------------------------------------

data "confluent_organization" "main" {}

data "confluent_service_account" "admin" {
  id = var.cc_service_account_id
}

resource "confluent_environment" "demo" {
  count        = var.cc_environment_id == "" ? 1 : 0
  display_name = "${var.cc_environment_name}-${var.demo_id}"

  stream_governance {
    package = "ESSENTIALS"
  }
}

locals {
  # Every name carries the demo id so the resources of one demo run are easy to find and clean up.
  prefix = "siem-${var.demo_id}"
  # Topics / Flink tables are <name>_<demo id> (e.g. zeek_conn_k3x9q2), so their Schema Registry
  # subjects - which live in the shared environment - never collide with another demo run.
  topic_suffix   = "_${var.demo_id}"
  environment_id = var.cc_environment_id != "" ? var.cc_environment_id : confluent_environment.demo[0].id
  admin_owner = {
    id          = data.confluent_service_account.admin.id
    api_version = data.confluent_service_account.admin.api_version
    kind        = data.confluent_service_account.admin.kind
  }
}

data "confluent_environment" "demo" {
  id = local.environment_id
}

resource "confluent_kafka_cluster" "standard" {
  display_name = "${var.cc_cluster_name}-${var.demo_id}"
  availability = "SINGLE_ZONE"
  cloud        = var.cc_cloud
  region       = var.cc_region
  standard {}

  environment {
    id = local.environment_id
  }
}

data "confluent_schema_registry_cluster" "sr" {
  environment {
    id = local.environment_id
  }
  depends_on = [confluent_kafka_cluster.standard]
}

# ---------------- API keys (owned by the bootstrap service account) ----------------

resource "confluent_api_key" "kafka" {
  display_name = "${local.prefix}-kafka"
  description  = "SIEM demo ${var.demo_id}: Kafka API key for Fluent Bit, Kafka Connect and the reference-data loader"

  owner {
    id          = local.admin_owner.id
    api_version = local.admin_owner.api_version
    kind        = local.admin_owner.kind
  }

  managed_resource {
    id          = confluent_kafka_cluster.standard.id
    api_version = confluent_kafka_cluster.standard.api_version
    kind        = confluent_kafka_cluster.standard.kind
    environment {
      id = local.environment_id
    }
  }
}

resource "confluent_api_key" "schema_registry" {
  display_name = "${local.prefix}-schema-registry"
  description  = "SIEM demo ${var.demo_id}: Schema Registry API key for Kafka Connect and the reference-data loader"

  owner {
    id          = local.admin_owner.id
    api_version = local.admin_owner.api_version
    kind        = local.admin_owner.kind
  }

  managed_resource {
    id          = data.confluent_schema_registry_cluster.sr.id
    api_version = data.confluent_schema_registry_cluster.sr.api_version
    kind        = data.confluent_schema_registry_cluster.sr.kind
    environment {
      id = local.environment_id
    }
  }
}

# Created only when demo.properties has no TABLEFLOW_API_KEY. An EnvironmentAdmin service account
# may not be allowed to mint Tableflow keys (403); then create the key in the console and pass it in.
resource "confluent_api_key" "tableflow" {
  count = var.tableflow_api_key == "" ? 1 : 0

  display_name = "${local.prefix}-tableflow"
  description  = "SIEM demo ${var.demo_id}: Tableflow API key (Tableflow + Iceberg REST catalog)"

  owner {
    id          = local.admin_owner.id
    api_version = local.admin_owner.api_version
    kind        = local.admin_owner.kind
  }

  managed_resource {
    id          = "tableflow"
    api_version = "tableflow/v1"
    kind        = "Tableflow"
    environment {
      id = local.environment_id
    }
  }
}

# ---------------- Raw landing topics (written by Fluent Bit, schemaless JSON) ----------------

locals {
  raw_topics = ["zeek_conn_raw", "zeek_dns_raw", "zeek_http_raw", "syslog_raw"]
}

resource "confluent_kafka_topic" "raw" {
  for_each = toset(local.raw_topics)

  kafka_cluster {
    id = confluent_kafka_cluster.standard.id
  }
  topic_name       = "${each.value}${local.topic_suffix}"
  partitions_count = 3
  rest_endpoint    = confluent_kafka_cluster.standard.rest_endpoint

  config = {
    # Raw JSON is a short-lived landing zone; the full-fidelity copy lives in Iceberg tables via Tableflow.
    "retention.ms" = "86400000"
  }

  credentials {
    key    = confluent_api_key.kafka.id
    secret = confluent_api_key.kafka.secret
  }
}

locals {
  tableflow_api_key    = var.tableflow_api_key != "" ? var.tableflow_api_key : confluent_api_key.tableflow[0].id
  tableflow_api_secret = var.tableflow_api_key != "" ? var.tableflow_api_secret : confluent_api_key.tableflow[0].secret
}
