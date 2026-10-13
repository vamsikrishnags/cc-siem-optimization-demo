-- Syslog (firewall, sshd, sudo, IAM, system) parsed from unstructured text. Full fidelity -> Tableflow -> Iceberg.
CREATE TABLE IF NOT EXISTS `syslog_events` (
  `host`          STRING,
  `event_time`    TIMESTAMP_LTZ(3),
  `app`           STRING,
  `pid`           INT,
  `facility`      INT,
  `severity`      INT,
  `event_type`    STRING,            -- firewall | authentication | privilege | iam | account | system
  `action`        STRING,
  `src_ip`        STRING,
  `src_port`      INT,
  `dst_ip`        STRING,
  `dst_port`      INT,
  `proto`         STRING,
  `user_name`     STRING,
  `message`       STRING,
  `raw_log`       STRING,
  WATERMARK FOR `event_time` AS `event_time` - INTERVAL '5' SECOND
)
DISTRIBUTED BY (`host`) INTO 3 BUCKETS
WITH (
  'kafka.retention.time' = '3 d'
);
