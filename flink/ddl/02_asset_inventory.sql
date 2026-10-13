-- Reference data: CMDB / asset inventory, upserted by the reference-loader container.
-- Each asset is stored twice: keyed by its IP (for network logs) and by its hostname (for syslog).
CREATE TABLE IF NOT EXISTS `asset_inventory` (
  `asset_id`    STRING NOT NULL,     -- IP address or hostname
  `ip`          STRING,
  `hostname`    STRING,
  `owner_team`  STRING,
  `department`  STRING,
  `criticality` STRING,              -- tier1 | tier2 | tier3
  `os`          STRING,
  `zone`        STRING,              -- dmz | corp | datacenter | guest
  PRIMARY KEY (`asset_id`) NOT ENFORCED
)
DISTRIBUTED BY (`asset_id`) INTO 1 BUCKETS
WITH (
  'changelog.mode'       = 'upsert',
  'value.format'         = 'avro-registry',
  'value.fields-include' = 'all',
  'kafka.cleanup-policy' = 'compact'
);
