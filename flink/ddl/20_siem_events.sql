-- Curated, enriched, PII-masked, ECS-shaped events: the ONLY stream sent to Elastic.
CREATE TABLE IF NOT EXISTS `siem_events` (
  `event_time`  TIMESTAMP_LTZ(3),
  `event`       ROW<`kind` STRING, `category` STRING, `action` STRING, `outcome` STRING,
                    `dataset` STRING, `severity` INT, `severity_label` STRING, `rule` STRING>,
  `source`      ROW<`ip` STRING, `port` INT>,
  `destination` ROW<`ip` STRING, `port` INT, `domain` STRING>,
  `network`     ROW<`transport` STRING, `protocol` STRING, `bytes` BIGINT>,
  `user`        ROW<`name` STRING>,
  `host`        ROW<`ip` STRING, `name` STRING, `owner_team` STRING, `department` STRING,
                    `criticality` STRING, `os` STRING, `zone` STRING>,
  `threat`      ROW<`matched` BOOLEAN, `indicator` STRING, `indicator_type` STRING, `category` STRING,
                    `name` STRING, `confidence` INT, `feed` STRING,
                    `country_iso_code` STRING, `geo_location` STRING>,
  `url`         ROW<`domain` STRING, `original` STRING>,
  `user_agent`  STRING,
  `message`     STRING,
  `observer`    STRING,
  `log_uid`     STRING,
  WATERMARK FOR `event_time` AS `event_time` - INTERVAL '5' SECOND
)
WITH (
  'kafka.retention.time' = '3 d'
);
