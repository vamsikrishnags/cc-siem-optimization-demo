-- =====================================================================================
-- Stage 2 - SIEM routing: Zeek dns.log             (~250 events/min in -> tens out)
--   USE CASE 1  FILTER : keep threat-intel / watchlist hits and DNS-tunneling patterns
--                        (very long encoded sub-domains); drop all other lookups
--   USE CASE 2  ENRICH : threat_intel on the exact name AND on the registered domain,
--                        asset_inventory on the querying client
--   USE CASE 3  SHAPE  : Elastic Common Schema-style nested fields
-- =====================================================================================
INSERT INTO `siem_events`
SELECT
  `event_time`,
  ROW(
    CASE WHEN sev >= 3 THEN 'alert' ELSE 'event' END,
    'network',
    'dns_query',
    CASE WHEN `rcode_name` = 'NOERROR' THEN 'success' ELSE 'failure' END,
    'zeek.dns',
    sev,
    CASE sev WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END,
    rule_name
  ),
  ROW(`src_ip`, `src_port`),
  ROW(`dst_ip`, `dst_port`, `query`),
  ROW(`proto`, 'dns', CAST(NULL AS BIGINT)),
  ROW(CAST(NULL AS STRING)),
  ROW(`src_ip`, a_hostname, a_owner_team, a_department, a_criticality, a_os, a_zone),
  ROW(ti_indicator IS NOT NULL, ti_indicator, ti_indicator_type, ti_category, ti_name, ti_confidence,
      ti_feed, ti_country, ti_geo),
  ROW(registered_domain, CAST(NULL AS STRING)),
  CAST(NULL AS STRING),
  CONCAT_WS(' ', 'dns', `qtype_name`, `query`, '->', `rcode_name`, 'from', `src_ip`),
  `sensor`,
  `uid`
FROM (
  SELECT
    j.*,
    CASE
      WHEN ti_indicator IS NOT NULL AND ti_category = 'adware'
        THEN 'Watchlist match: ad / tracking domain'
      WHEN ti_indicator IS NOT NULL
        THEN CONCAT('Threat intel match: ', ti_category)
      WHEN CHAR_LENGTH(first_label) >= 50
        THEN 'Possible DNS tunneling (long encoded sub-domain)'
    END AS rule_name,
    GREATEST(
      COALESCE(CASE ti_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END, 0),
      CASE WHEN CHAR_LENGTH(first_label) >= 50 THEN 3 ELSE 0 END
    ) AS sev
  FROM (
    SELECT
      d.*,
      COALESCE(tq.`indicator`,       td.`indicator`)       AS ti_indicator,
      COALESCE(tq.`indicator_type`,  td.`indicator_type`)  AS ti_indicator_type,
      COALESCE(tq.`threat_category`, td.`threat_category`) AS ti_category,
      COALESCE(tq.`threat_name`,     td.`threat_name`)     AS ti_name,
      COALESCE(tq.`severity`,        td.`severity`)        AS ti_severity,
      COALESCE(tq.`confidence`,      td.`confidence`)      AS ti_confidence,
      COALESCE(tq.`feed`,            td.`feed`)            AS ti_feed,
      COALESCE(tq.`country_iso`,     td.`country_iso`)     AS ti_country,
      COALESCE(tq.`geo_location`,    td.`geo_location`)    AS ti_geo,
      a.`hostname`    AS a_hostname,
      a.`owner_team`  AS a_owner_team,
      a.`department`  AS a_department,
      a.`criticality` AS a_criticality,
      a.`os`          AS a_os,
      a.`zone`        AS a_zone
    FROM (
      SELECT
        *,
        REGEXP_EXTRACT(`query`, '([^.]+\.[^.]+)$', 1) AS registered_domain,
        REGEXP_EXTRACT(`query`, '^([^.]+)', 1)        AS first_label
      FROM `zeek_dns`
      WHERE `query` IS NOT NULL
    ) AS d
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF d.`event_time` AS tq
      ON d.`query` = tq.`indicator`
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF d.`event_time` AS td
      ON d.registered_domain = td.`indicator`
    LEFT JOIN `asset_inventory` FOR SYSTEM_TIME AS OF d.`event_time` AS a
      ON d.`src_ip` = a.`asset_id`
  ) AS j
) AS r
WHERE rule_name IS NOT NULL;
