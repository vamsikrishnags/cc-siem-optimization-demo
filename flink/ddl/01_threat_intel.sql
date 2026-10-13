-- Reference data: threat-intel indicators (IPs and domains), upserted by the reference-loader container.
-- Used as a versioned table in temporal joins (enrichment use case).
CREATE TABLE IF NOT EXISTS `threat_intel` (
  `indicator`       STRING NOT NULL,
  `indicator_type`  STRING,          -- ip | domain
  `threat_category` STRING,          -- exfiltration | c2 | bruteforce | malware | dga | adware
  `threat_name`     STRING,
  `severity`        STRING,          -- critical | high | medium | low
  `confidence`      INT,
  `feed`            STRING,
  `country_iso`     STRING,
  `geo_location`    STRING,          -- "lat,lon" (Elasticsearch geo_point string form)
  PRIMARY KEY (`indicator`) NOT ENFORCED
)
DISTRIBUTED BY (`indicator`) INTO 1 BUCKETS
WITH (
  'changelog.mode'       = 'upsert',
  'value.format'         = 'avro-registry',
  'value.fields-include' = 'all',
  'kafka.cleanup-policy' = 'compact'
);
