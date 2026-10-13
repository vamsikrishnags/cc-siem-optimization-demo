-- Normalized, schematized Zeek http.log. Full fidelity -> Tableflow -> Iceberg.
CREATE TABLE IF NOT EXISTS `zeek_http` (
  `uid`               STRING,
  `event_time`        TIMESTAMP_LTZ(3),
  `zeek_ts`           DOUBLE,
  `sensor`            STRING,
  `src_ip`            STRING,
  `src_port`          INT,
  `dst_ip`            STRING,
  `dst_port`          INT,
  `method`            STRING,
  `host`              STRING,
  `uri`               STRING,
  `referrer`          STRING,
  `user_agent`        STRING,
  `status_code`       INT,
  `request_body_len`  BIGINT,
  `response_body_len` BIGINT,
  `resp_mime_types`   STRING,
  `raw_log`           STRING,
  WATERMARK FOR `event_time` AS `event_time` - INTERVAL '5' SECOND
)
DISTRIBUTED BY (`uid`) INTO 3 BUCKETS
WITH (
  'kafka.retention.time' = '3 d'
);
