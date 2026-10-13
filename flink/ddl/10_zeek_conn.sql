-- Normalized, schematized Zeek conn.log. Full fidelity (incl. raw_log) -> Tableflow -> Iceberg.
CREATE TABLE IF NOT EXISTS `zeek_conn` (
  `uid`         STRING,
  `event_time`  TIMESTAMP_LTZ(3),
  `zeek_ts`     DOUBLE,
  `sensor`      STRING,
  `src_ip`      STRING,
  `src_port`    INT,
  `dst_ip`      STRING,
  `dst_port`    INT,
  `proto`       STRING,
  `service`     STRING,
  `duration`    DOUBLE,
  `orig_bytes`  BIGINT,
  `resp_bytes`  BIGINT,
  `conn_state`  STRING,
  `local_orig`  BOOLEAN,
  `local_resp`  BOOLEAN,
  `history`     STRING,
  `orig_pkts`   BIGINT,
  `resp_pkts`   BIGINT,
  `raw_log`     STRING,
  WATERMARK FOR `event_time` AS `event_time` - INTERVAL '5' SECOND
)
DISTRIBUTED BY (`uid`) INTO 3 BUCKETS
WITH (
  'kafka.retention.time' = '3 d'
);
