-- =====================================================================================
-- Stage 2 - SIEM routing: Zeek http.log            (~20 events/min in -> a few out)
--   USE CASE 1  FILTER : keep threat-intel hits (host, registered domain or IP), web
--                        attack patterns and offensive-tool user agents
--   USE CASE 2  ENRICH : threat_intel + asset_inventory temporal joins
--   USE CASE 3  MASK   : redact credentials / tokens / e-mails in query strings
-- =====================================================================================
INSERT INTO `siem_events`
SELECT
  `event_time`,
  ROW(
    CASE WHEN sev >= 3 THEN 'alert' ELSE 'event' END,
    'web',
    LOWER(COALESCE(`method`, 'request')),
    CASE WHEN `status_code` < 400 THEN 'success' ELSE 'failure' END,
    'zeek.http',
    sev,
    CASE sev WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END,
    rule_name
  ),
  ROW(`src_ip`, `src_port`),
  ROW(`dst_ip`, `dst_port`, `host`),
  ROW('tcp', 'http', COALESCE(`request_body_len`, 0) + COALESCE(`response_body_len`, 0)),
  ROW(CAST(NULL AS STRING)),
  ROW(`src_ip`, a_hostname, a_owner_team, a_department, a_criticality, a_os, a_zone),
  ROW(ti_indicator IS NOT NULL, ti_indicator, ti_indicator_type, ti_category, ti_name, ti_confidence,
      ti_feed, ti_country, ti_geo),
  ROW(`host`, masked_uri),
  `user_agent`,
  CONCAT_WS(' ', 'http', `method`, CONCAT(`host`, masked_uri), '->', CAST(`status_code` AS STRING),
            CONCAT('sent=', CAST(COALESCE(`request_body_len`, 0) AS STRING))),
  `sensor`,
  `uid`
FROM (
  SELECT
    j.*,
    -- PII / secret masking: keep the parameter name, drop the value
    -- (Flink treats the replacement literally, so the patterns use look-arounds)
    REGEXP_REPLACE(
      REGEXP_REPLACE(`uri`, '(?i)(?<=[?&](password|passwd|pwd|token|api_key|apikey|secret|session|sid|email|user)=)[^&]*', '[REDACTED]'),
      '[A-Za-z0-9._%+-]+(@|%40)[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[EMAIL]'
    ) AS masked_uri,
    CASE
      WHEN ti_indicator IS NOT NULL AND ti_category = 'adware'
        THEN 'Watchlist match: ad / tracking domain'
      WHEN ti_indicator IS NOT NULL
        THEN CONCAT('Threat intel match: ', ti_category)
      WHEN REGEXP(COALESCE(`uri`, ''), '(?i)(union(\s|%20|\+)+select|\.\./|%2e%2e%2f|<script|%3cscript|/etc/passwd|cmd\.exe|/wp-login\.php|xmlrpc\.php)')
        THEN 'Web attack pattern in URI'
      WHEN REGEXP(COALESCE(`user_agent`, ''), '(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan)')
        THEN 'Offensive security tool user agent'
    END AS rule_name,
    GREATEST(
      COALESCE(CASE ti_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END, 0),
      CASE WHEN REGEXP(COALESCE(`uri`, ''), '(?i)(union(\s|%20|\+)+select|\.\./|%2e%2e%2f|<script|%3cscript|/etc/passwd|cmd\.exe)') THEN 3 ELSE 0 END,
      CASE WHEN REGEXP(COALESCE(`user_agent`, ''), '(?i)(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wpscan)') THEN 2 ELSE 0 END,
      1
    ) AS sev
  FROM (
    SELECT
      h.*,
      COALESCE(th.`indicator`,       td.`indicator`,       ti.`indicator`)       AS ti_indicator,
      COALESCE(th.`indicator_type`,  td.`indicator_type`,  ti.`indicator_type`)  AS ti_indicator_type,
      COALESCE(th.`threat_category`, td.`threat_category`, ti.`threat_category`) AS ti_category,
      COALESCE(th.`threat_name`,     td.`threat_name`,     ti.`threat_name`)     AS ti_name,
      COALESCE(th.`severity`,        td.`severity`,        ti.`severity`)        AS ti_severity,
      COALESCE(th.`confidence`,      td.`confidence`,      ti.`confidence`)      AS ti_confidence,
      COALESCE(th.`feed`,            td.`feed`,            ti.`feed`)            AS ti_feed,
      COALESCE(th.`country_iso`,     td.`country_iso`,     ti.`country_iso`)     AS ti_country,
      COALESCE(th.`geo_location`,    td.`geo_location`,    ti.`geo_location`)    AS ti_geo,
      a.`hostname`    AS a_hostname,
      a.`owner_team`  AS a_owner_team,
      a.`department`  AS a_department,
      a.`criticality` AS a_criticality,
      a.`os`          AS a_os,
      a.`zone`        AS a_zone
    FROM (
      SELECT *, REGEXP_EXTRACT(`host`, '([^.]+\.[^.]+)$', 1) AS registered_domain
      FROM `zeek_http`
    ) AS h
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF h.`event_time` AS th
      ON h.`host` = th.`indicator`
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF h.`event_time` AS td
      ON h.registered_domain = td.`indicator`
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF h.`event_time` AS ti
      ON h.`dst_ip` = ti.`indicator`
    LEFT JOIN `asset_inventory` FOR SYSTEM_TIME AS OF h.`event_time` AS a
      ON h.`src_ip` = a.`asset_id`
  ) AS j
) AS r
WHERE rule_name IS NOT NULL;
