-- Per-minute event counts before (ingested) and after (siem) the pipeline -> Kibana "volume reduction".
CREATE TABLE IF NOT EXISTS `pipeline_metrics` (
  `metric_time`  TIMESTAMP_LTZ(3),
  `stage`        STRING,             -- ingested | siem
  `dataset`      STRING,
  `event_count`  BIGINT
)
WITH (
  'kafka.retention.time' = '3 d'
);
