output "demo_id" {
  value = var.demo_id
}

output "organization_id" {
  value = data.confluent_organization.main.id
}

output "environment_id" {
  value = local.environment_id
}

output "environment_name" {
  value = data.confluent_environment.demo.display_name
}

output "kafka_cluster_id" {
  value = confluent_kafka_cluster.standard.id
}

output "kafka_cluster_name" {
  value = confluent_kafka_cluster.standard.display_name
}

output "kafka_bootstrap" {
  value = replace(confluent_kafka_cluster.standard.bootstrap_endpoint, "SASL_SSL://", "")
}

output "kafka_api_key" {
  value = confluent_api_key.kafka.id
}

output "kafka_api_secret" {
  value     = confluent_api_key.kafka.secret
  sensitive = true
}

output "schema_registry_url" {
  value = data.confluent_schema_registry_cluster.sr.rest_endpoint
}

output "schema_registry_api_key" {
  value = confluent_api_key.schema_registry.id
}

output "schema_registry_api_secret" {
  value     = confluent_api_key.schema_registry.secret
  sensitive = true
}

output "flink_compute_pool_id" {
  value = confluent_flink_compute_pool.main.id
}

output "flink_rest_endpoint" {
  value = data.confluent_flink_region.main.rest_endpoint
}

output "tableflow_catalog_endpoint" {
  value = local.tableflow_catalog_endpoint
}

output "tableflow_api_key" {
  value = local.tableflow_api_key
}

output "tableflow_api_secret" {
  value     = local.tableflow_api_secret
  sensitive = true
}

output "tableflow_tables" {
  value = { for k, t in confluent_tableflow_topic.lake : k => t.table_path }
}
