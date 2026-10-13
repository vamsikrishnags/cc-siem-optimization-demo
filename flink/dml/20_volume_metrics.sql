-- =====================================================================================
-- Volume reduction metrics: per-minute event counts entering the pipeline vs. leaving
-- for the SIEM. Sent to Elastic next to the alerts so Kibana can show the reduction %.
-- =====================================================================================
INSERT INTO `pipeline_metrics`
SELECT window_time, 'ingested', 'zeek.conn', COUNT(*)
FROM TABLE(TUMBLE(TABLE `zeek_conn`, DESCRIPTOR(`event_time`), INTERVAL '1' MINUTE))
GROUP BY window_start, window_end, window_time
UNION ALL
SELECT window_time, 'ingested', 'zeek.dns', COUNT(*)
FROM TABLE(TUMBLE(TABLE `zeek_dns`, DESCRIPTOR(`event_time`), INTERVAL '1' MINUTE))
GROUP BY window_start, window_end, window_time
UNION ALL
SELECT window_time, 'ingested', 'zeek.http', COUNT(*)
FROM TABLE(TUMBLE(TABLE `zeek_http`, DESCRIPTOR(`event_time`), INTERVAL '1' MINUTE))
GROUP BY window_start, window_end, window_time
UNION ALL
SELECT window_time, 'ingested', 'syslog', COUNT(*)
FROM TABLE(TUMBLE(TABLE `syslog_events`, DESCRIPTOR(`event_time`), INTERVAL '1' MINUTE))
GROUP BY window_start, window_end, window_time
UNION ALL
SELECT window_time, 'siem', `event`.`dataset`, COUNT(*)
FROM TABLE(TUMBLE(TABLE `siem_events`, DESCRIPTOR(`event_time`), INTERVAL '1' MINUTE))
GROUP BY window_start, window_end, window_time, `event`.`dataset`;
