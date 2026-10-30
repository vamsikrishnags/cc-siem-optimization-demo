# ---------------------------------------------------------------------------
# Confluent Cloud for Apache Flink: compute pool + all SQL statements.
# Statement text lives in ../flink/{ddl,dml}; Terraform only orders and submits it.
# ---------------------------------------------------------------------------

data "confluent_flink_region" "main" {
  cloud  = var.cc_cloud
  region = var.cc_region
}

resource "confluent_flink_compute_pool" "main" {
  display_name = "${local.prefix}-pool"
  cloud        = var.cc_cloud
  region       = var.cc_region
  max_cfu      = var.cc_flink_max_cfu

  environment {
    id = local.environment_id
  }
}

resource "confluent_api_key" "flink" {
  display_name = "${local.prefix}-flink"
  description  = "SIEM demo ${var.demo_id}: Flink API key used by Terraform to submit statements"

  owner {
    id          = local.admin_owner.id
    api_version = local.admin_owner.api_version
    kind        = local.admin_owner.kind
  }

  managed_resource {
    id          = data.confluent_flink_region.main.id
    api_version = data.confluent_flink_region.main.api_version
    kind        = data.confluent_flink_region.main.kind
    environment {
      id = local.environment_id
    }
  }
}

locals {
  flink_sql_dir = "${path.module}/../flink"

  # The SQL files use the short table names (`zeek_conn`, `siem_events`, ...); every backticked
  # table name gets the demo id appended at submit time (`zeek_conn` -> `zeek_conn_k3x9q2`).
  # scripts/07-flink-sql.sh does the same for the ad-hoc demo queries (keep the list in sync with scripts/lib.sh).
  flink_table_regex = "/`(${join("|", concat(local.raw_topics, local.lake_topics,
  ["siem_events", "pipeline_metrics", "threat_intel", "asset_inventory"]))})`/"
  flink_table_name = "`$${1}${local.topic_suffix}`"

  flink_catalog_properties = {
    "sql.current-catalog"  = data.confluent_environment.demo.display_name
    "sql.current-database" = confluent_kafka_cluster.standard.display_name
  }

  # Long-running statements: mark quiet partitions idle quickly so watermarks
  # (and therefore temporal joins and windows) keep moving in a low-volume demo.
  flink_streaming_properties = merge(local.flink_catalog_properties, {
    "sql.tables.scan.idle-timeout" = "10 s"
  })

  # Tables are created first (order inside this map does not matter).
  ddl_statements = {
    "threat-intel"     = "ddl/01_threat_intel.sql"
    "asset-inventory"  = "ddl/02_asset_inventory.sql"
    "zeek-conn"        = "ddl/10_zeek_conn.sql"
    "zeek-dns"         = "ddl/11_zeek_dns.sql"
    "zeek-http"        = "ddl/12_zeek_http.sql"
    "syslog-events"    = "ddl/13_syslog_events.sql"
    "siem-events"      = "ddl/20_siem_events.sql"
    "pipeline-metrics" = "ddl/21_pipeline_metrics.sql"
  }

  # Watermark tweaks on the reference tables used as versioned tables in temporal joins.
  alter_statements = {
    "threat-intel-watermark"    = "ddl/30_alter_watermarks_threat_intel.sql"
    "asset-inventory-watermark" = "ddl/31_alter_watermarks_asset_inventory.sql"
  }

  # Continuous pipelines. The PII salt is injected into the masking SQL.
  dml_statements = {
    "normalize"      = "dml/01_normalize_raw_logs.sql"
    "siem-network"   = "dml/10_siem_network.sql"
    "siem-dns"       = "dml/11_siem_dns.sql"
    "siem-http"      = "dml/12_siem_http.sql"
    "siem-syslog"    = "dml/13_siem_syslog.sql"
    "volume-metrics" = "dml/20_volume_metrics.sql"
  }
}

resource "confluent_flink_statement" "ddl" {
  for_each = local.ddl_statements

  statement_name = "${local.prefix}-ddl-${each.key}"
  statement      = replace(file("${local.flink_sql_dir}/${each.value}"), local.flink_table_regex, local.flink_table_name)
  properties     = local.flink_catalog_properties

  organization {
    id = data.confluent_organization.main.id
  }
  environment {
    id = local.environment_id
  }
  compute_pool {
    id = confluent_flink_compute_pool.main.id
  }
  principal {
    id = data.confluent_service_account.admin.id
  }
  rest_endpoint = data.confluent_flink_region.main.rest_endpoint
  credentials {
    key    = confluent_api_key.flink.id
    secret = confluent_api_key.flink.secret
  }

  depends_on = [confluent_kafka_topic.raw]
}

resource "confluent_flink_statement" "alter" {
  for_each = local.alter_statements

  statement_name = "${local.prefix}-ddl-${each.key}"
  statement      = replace(file("${local.flink_sql_dir}/${each.value}"), local.flink_table_regex, local.flink_table_name)
  properties     = local.flink_catalog_properties

  organization {
    id = data.confluent_organization.main.id
  }
  environment {
    id = local.environment_id
  }
  compute_pool {
    id = confluent_flink_compute_pool.main.id
  }
  principal {
    id = data.confluent_service_account.admin.id
  }
  rest_endpoint = data.confluent_flink_region.main.rest_endpoint
  credentials {
    key    = confluent_api_key.flink.id
    secret = confluent_api_key.flink.secret
  }

  depends_on = [confluent_flink_statement.ddl]
}

resource "confluent_flink_statement" "dml" {
  for_each = local.dml_statements

  statement_name = "${local.prefix}-${each.key}"
  statement = replace(
    replace(file("${local.flink_sql_dir}/${each.value}"), local.flink_table_regex, local.flink_table_name),
    "__PII_SALT__", var.pii_hash_salt
  )
  properties = local.flink_streaming_properties

  organization {
    id = data.confluent_organization.main.id
  }
  environment {
    id = local.environment_id
  }
  compute_pool {
    id = confluent_flink_compute_pool.main.id
  }
  principal {
    id = data.confluent_service_account.admin.id
  }
  rest_endpoint = data.confluent_flink_region.main.rest_endpoint
  credentials {
    key    = confluent_api_key.flink.id
    secret = confluent_api_key.flink.secret
  }

  depends_on = [confluent_flink_statement.alter]
}
