-- =====================================================================================
-- Stage 2 - SIEM routing: Zeek conn.log            (~330 events/min in -> ~1 out)
--   USE CASE 1  FILTER : keep threat-intel hits, large outbound transfers, inbound
--                        connections to sensitive services and outbound connections on
--                        non-standard ports; drop routine traffic
--                        (long-running connections arrive as interim records every 5 MB,
--                         see docker/zeek/long-connections.zeek)
--   USE CASE 2  ENRICH : event-time temporal joins against threat_intel (remote IP)
--                        and asset_inventory (local IP)
--   USE CASE 3  SHAPE  : Elastic Common Schema-style nested fields
-- =====================================================================================
INSERT INTO `siem_events`
SELECT
  `event_time`,
  ROW(
    CASE WHEN sev >= 3 THEN 'alert' ELSE 'event' END,
    'network',
    'connection',
    CASE WHEN `conn_state` IN ('SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR', 'OTH') THEN 'success' ELSE 'failure' END,
    'zeek.conn',
    sev,
    CASE sev WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END,
    rule_name
  ),
  ROW(`src_ip`, `src_port`),
  ROW(`dst_ip`, `dst_port`, CAST(NULL AS STRING)),
  ROW(`proto`, `service`, COALESCE(`orig_bytes`, 0) + COALESCE(`resp_bytes`, 0)),
  ROW(CAST(NULL AS STRING)),
  ROW(local_ip, a_hostname, a_owner_team, a_department, a_criticality, a_os, a_zone),
  ROW(ti_indicator IS NOT NULL, ti_indicator, ti_indicator_type, ti_category, ti_name, ti_confidence,
      ti_feed, ti_country, ti_geo),
  ROW(CAST(NULL AS STRING), CAST(NULL AS STRING)),
  CAST(NULL AS STRING),
  CONCAT_WS(' ', 'conn', CONCAT(`src_ip`, ':', CAST(`src_port` AS STRING)), '->',
            CONCAT(`dst_ip`, ':', CAST(`dst_port` AS STRING)), `proto`, `service`,
            CONCAT('sent=', CAST(COALESCE(`orig_bytes`, 0) AS STRING)),
            CONCAT('recv=', CAST(COALESCE(`resp_bytes`, 0) AS STRING)), `conn_state`),
  `sensor`,
  `uid`
FROM (
  SELECT
    j.*,
    CASE
      WHEN ti_indicator IS NOT NULL
        THEN CONCAT('Threat intel match: ', ti_category)
      WHEN local_orig_b AND NOT local_resp_b AND COALESCE(`orig_bytes`, 0) >= 5000000
        THEN 'Large outbound transfer (possible exfiltration)'
      WHEN NOT local_orig_b AND local_resp_b AND `dst_port` IN (22, 23, 445, 1433, 3306, 3389, 5432, 5900)
        THEN 'Inbound connection to sensitive service'
      WHEN nonstandard_outbound
        THEN 'Outbound connection on non-standard port'
    END AS rule_name,
    GREATEST(
      COALESCE(CASE ti_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END, 0),
      CASE WHEN local_orig_b AND NOT local_resp_b AND COALESCE(`orig_bytes`, 0) >= 5000000 THEN 3 ELSE 0 END,
      CASE WHEN NOT local_orig_b AND local_resp_b THEN 2 ELSE 0 END,
      CASE WHEN nonstandard_outbound THEN 2 ELSE 0 END
    ) AS sev
  FROM (
    SELECT
      c.*,
      ti.`indicator`       AS ti_indicator,
      ti.`indicator_type`  AS ti_indicator_type,
      ti.`threat_category` AS ti_category,
      ti.`threat_name`     AS ti_name,
      ti.`severity`        AS ti_severity,
      ti.`confidence`      AS ti_confidence,
      ti.`feed`            AS ti_feed,
      ti.`country_iso`     AS ti_country,
      ti.`geo_location`    AS ti_geo,
      a.`hostname`         AS a_hostname,
      a.`owner_team`       AS a_owner_team,
      a.`department`       AS a_department,
      a.`criticality`      AS a_criticality,
      a.`os`               AS a_os,
      a.`zone`             AS a_zone
    FROM (
      SELECT
        *,
        COALESCE(`local_orig`, FALSE) AS local_orig_b,
        COALESCE(`local_resp`, FALSE) AS local_resp_b,
        CASE WHEN COALESCE(`local_orig`, FALSE) THEN `dst_ip` ELSE `src_ip` END AS remote_ip,
        CASE WHEN COALESCE(`local_orig`, FALSE) THEN `src_ip` ELSE `dst_ip` END AS local_ip,
        -- internal host -> internet on a port outside the usual web / DNS / NTP / discovery set
        COALESCE(`local_orig`, FALSE) AND NOT COALESCE(`local_resp`, FALSE)
          AND `proto` IN ('tcp', 'udp')
          AND NOT REGEXP(COALESCE(`dst_ip`, ''), '^(224\.|239\.|255\.|ff0)')
          AND `dst_port` NOT IN (53, 67, 68, 80, 123, 137, 138, 443, 853, 1900, 3478, 5353, 5355, 8080)
          AS nonstandard_outbound
      FROM `zeek_conn`
    ) AS c
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF c.`event_time` AS ti
      ON c.remote_ip = ti.`indicator`
    LEFT JOIN `asset_inventory` FOR SYSTEM_TIME AS OF c.`event_time` AS a
      ON c.local_ip = a.`asset_id`
  ) AS j
) AS r
WHERE rule_name IS NOT NULL;
