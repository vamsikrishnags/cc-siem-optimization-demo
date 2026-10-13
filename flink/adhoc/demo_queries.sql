-- ---------------------------------------------------------------------------------------
-- 1. Raw, schemaless JSON exactly as Fluent Bit wrote it
-- ---------------------------------------------------------------------------------------
SELECT CAST(`val` AS STRING) AS raw_json FROM `syslog_raw` LIMIT 10;

-- ---------------------------------------------------------------------------------------
-- 2. The same events after normalization (typed, Schema Registry governed, lake-bound)
-- ---------------------------------------------------------------------------------------
SELECT event_time, `host`, event_type, `action`, src_ip, dst_ip, dst_port, user_name, message
FROM `syslog_events` LIMIT 20;

-- ---------------------------------------------------------------------------------------
-- 3. Live volume reduction - ingested vs. sent to the SIEM, per minute
-- ---------------------------------------------------------------------------------------
SELECT metric_time,
       SUM(CASE WHEN stage = 'ingested' THEN event_count ELSE 0 END) AS ingested,
       SUM(CASE WHEN stage = 'siem'     THEN event_count ELSE 0 END) AS to_siem
FROM `pipeline_metrics`
GROUP BY metric_time;

-- ---------------------------------------------------------------------------------------
-- 4. What the SIEM receives: enriched + masked alerts
-- ---------------------------------------------------------------------------------------
SELECT event_time, `event`.severity_label, `event`.`rule`, source.ip, destination.domain,
       `user`.name, `host`.name, `host`.criticality, threat.name, message
FROM `siem_events`
WHERE `event`.severity >= 3;

-- ---------------------------------------------------------------------------------------
-- 5. Live threat-intel update (or: docker compose run --rm reference-loader add-indicator ...)
--    198.51.100.200 is the synthetic port scanner. Today only its probes on sensitive ports
--    reach the SIEM; once it is an indicator, every packet it sends is flagged within seconds -
--    no SIEM rule change and no reprocessing needed.
-- ---------------------------------------------------------------------------------------
INSERT INTO `threat_intel` VALUES
  ('198.51.100.200', 'ip', 'scanner', 'Mass port scanner (analyst-added, live demo)', 'high', 90,
   'analyst (live demo)', 'US', '37.751,-97.822');
