-- Normalized, schematized Zeek dns.log. Full fidelity -> Tableflow -> Iceberg.
CREATE TABLE IF NOT EXISTS `zeek_dns` (
  `uid`         STRING,
  `event_time`  TIMESTAMP_LTZ(3),
  `zeek_ts`     DOUBLE,
  `sensor`      STRING,
  `src_ip`      STRING,
  `src_port`    INT,
  `dst_ip`      STRING,
  `dst_port`    INT,
  `proto`       STRING,
  `query`       STRING,
  `qtype_name`  STRING,
  `rcode_name`  STRING,
  `answers`     STRING,
  `rejected`    BOOLEAN,
  `raw_log`     STRING,
  WATERMARK FOR `event_time` AS `event_time` - INTERVAL '5' SECOND
)
DISTRIBUTED BY (`uid`) INTO 3 BUCKETS
WITH (
  'kafka.retention.time' = '3 d'
);
