# ---------------------------------------------------------------------------
# Tableflow: materialize the full-fidelity (unfiltered, unmasked) normalized
# log topics as Apache Iceberg tables in Confluent-managed storage.
# Query them through Tableflow's Iceberg REST catalog (see scripts/03-lake-query.sh).
# ---------------------------------------------------------------------------

locals {
  lake_topics = ["zeek_conn", "zeek_dns", "zeek_http", "syslog_events"]

  # Iceberg REST catalog of this environment (the cluster id is the namespace, topics are tables)
  tableflow_catalog_endpoint = "https://tableflow.${var.cc_region}.${lower(var.cc_cloud)}.confluent.cloud/iceberg/catalog/organizations/${data.confluent_organization.main.id}/environments/${local.environment_id}"
}

resource "confluent_tableflow_topic" "lake" {
  for_each = toset(local.lake_topics)

  display_name  = each.value
  table_formats = ["ICEBERG"] # Confluent-managed storage materializes Iceberg (Delta needs bring-your-own storage)

  environment {
    id = local.environment_id
  }
  kafka_cluster {
    id = confluent_kafka_cluster.standard.id
  }

  managed_storage {}

  credentials {
    key    = local.tableflow_api_key
    secret = local.tableflow_api_secret
  }

  # topics + schemas are created by the Flink DDL
  depends_on = [confluent_flink_statement.ddl]
}
