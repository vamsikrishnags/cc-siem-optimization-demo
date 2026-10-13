-- =====================================================================================
-- Stage 2 - SIEM routing: syslog (firewall, sshd, sudo, IAM, account service)
--                                                  (~2,400 events/min in -> ~20 out)
--   USE CASE 1  FILTER : drop routine firewall ACCEPTs, background-noise DROPs, cron,
--                        systemd, NTP, health checks, internal key-based logins, routine sudo
--   USE CASE 2  ENRICH : threat_intel on the remote IP, asset_inventory on the target host
--   USE CASE 3  MASK   : pseudonymize user names (salted SHA-256) and strip e-mails /
--                        user names out of the free-text message before it leaves Confluent
-- =====================================================================================
INSERT INTO `siem_events`
SELECT
  `event_time`,
  ROW(
    CASE WHEN sev >= 3 THEN 'alert' ELSE 'event' END,
    `event_type`,
    `action`,
    CASE
      WHEN `action` IN ('login_failed', 'invalid_user', 'DROP', 'REJECT') THEN 'failure'
      ELSE 'success'
    END,
    'syslog',
    sev,
    CASE sev WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END,
    rule_name
  ),
  ROW(`src_ip`, `src_port`),
  ROW(`dst_ip`, `dst_port`, CAST(NULL AS STRING)),
  ROW(`proto`, CASE WHEN `event_type` = 'authentication' THEN 'ssh' END, CAST(NULL AS BIGINT)),
  -- pseudonymized identity: stable per user (so analysts can still correlate), not reversible
  ROW(CASE WHEN `user_name` IS NOT NULL
           THEN CONCAT('user-', SUBSTRING(SHA256(CONCAT('__PII_SALT__', LOWER(`user_name`))), 1, 12))
      END),
  ROW(a_ip, COALESCE(a_hostname, `host`), a_owner_team, a_department, a_criticality, a_os, a_zone),
  ROW(ti_indicator IS NOT NULL, ti_indicator, ti_indicator_type, ti_category, ti_name, ti_confidence,
      ti_feed, ti_country, ti_geo),
  ROW(CAST(NULL AS STRING), CAST(NULL AS STRING)),
  CAST(NULL AS STRING),
  -- free-text masking (Flink treats the replacement literally, so the patterns use look-arounds)
  REGEXP_REPLACE(
  REGEXP_REPLACE(
  REGEXP_REPLACE(
  REGEXP_REPLACE(
  REGEXP_REPLACE(
  REGEXP_REPLACE(`message`,
    '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', '[EMAIL]'),   -- e-mail addresses
    '[^ ]+(?= from [0-9a-fA-F:.]+ port)', '[USER]'),                  -- sshd: "... for <user> from <ip> port"
    '^ *[^ ]+(?= : TTY=)', '[USER]'),                                 -- sudo: "<user> : TTY=..."
    '(?<=/home/)[^ ;/,]+', '[USER]'),                                 -- home directories
    '(?<=name=)[^,]+', '[USER]'),                                     -- useradd: "name=<user>,"
    '(?<=add '')[^'']+(?='' to group)', '[USER]'),                    -- usermod: "add '<user>' to group"
  `host`,
  CAST(NULL AS STRING)
FROM (
  SELECT
    j.*,
    CASE
      WHEN ti_indicator IS NOT NULL AND `event_type` = 'firewall' AND `action` = 'ACCEPT'
        THEN 'Allowed traffic with threat-intel IP'
      WHEN `event_type` = 'authentication' AND `action` = 'login_success' AND src_external
        THEN 'Successful SSH login from external IP'
      WHEN `event_type` = 'authentication' AND `action` IN ('login_failed', 'invalid_user')
        THEN 'SSH authentication failure'
      WHEN `event_type` = 'iam'
        THEN 'Local account or group change'
      WHEN `event_type` = 'privilege'
           AND REGEXP(`message`, '(useradd|usermod|passwd|visudo|/etc/shadow|chmod 777|nc -e|bash -i)')
        THEN 'Suspicious privileged command'
      WHEN `event_type` = 'account'
        THEN 'Account security change'
      WHEN `event_type` = 'firewall' AND `action` IN ('DROP', 'REJECT') AND src_external
           AND `dst_port` IN (22, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200)
        THEN 'Blocked inbound probe to sensitive service'
      WHEN ti_indicator IS NOT NULL
        THEN CONCAT('Threat intel match: ', ti_category)
    END AS rule_name,
    GREATEST(
      COALESCE(CASE ti_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 END, 0),
      CASE
        WHEN `event_type` = 'authentication' AND `action` = 'login_success' AND src_external THEN 4
        WHEN `event_type` IN ('iam', 'privilege') THEN 3
        WHEN `event_type` = 'authentication' THEN 2
        WHEN `event_type` = 'firewall' THEN 2
        WHEN `event_type` = 'account' AND `message` LIKE '%removed%' THEN 2
        ELSE 1
      END
    ) AS sev
  FROM (
    SELECT
      s.*,
      ti.`indicator`       AS ti_indicator,
      ti.`indicator_type`  AS ti_indicator_type,
      ti.`threat_category` AS ti_category,
      ti.`threat_name`     AS ti_name,
      ti.`severity`        AS ti_severity,
      ti.`confidence`      AS ti_confidence,
      ti.`feed`            AS ti_feed,
      ti.`country_iso`     AS ti_country,
      ti.`geo_location`    AS ti_geo,
      a.`ip`               AS a_ip,
      a.`hostname`         AS a_hostname,
      a.`owner_team`       AS a_owner_team,
      a.`department`       AS a_department,
      a.`criticality`      AS a_criticality,
      a.`os`               AS a_os,
      a.`zone`             AS a_zone
    FROM (
      SELECT
        *,
        `src_ip` IS NOT NULL
          AND NOT REGEXP(`src_ip`, '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)') AS src_external,
        -- firewall: the "other side" of the connection; auth/account: the client
        CASE
          WHEN `event_type` = 'firewall' AND REGEXP(COALESCE(`src_ip`, ''), '^(10\.|192\.168\.)') THEN `dst_ip`
          ELSE `src_ip`
        END AS remote_ip,
        -- firewall: the internal side (by IP); everything else: the reporting host (by name)
        CASE
          WHEN `event_type` = 'firewall' AND REGEXP(COALESCE(`src_ip`, ''), '^(10\.|192\.168\.)') THEN `src_ip`
          WHEN `event_type` = 'firewall' THEN `dst_ip`
          ELSE `host`
        END AS asset_key
      FROM `syslog_events`
    ) AS s
    LEFT JOIN `threat_intel` FOR SYSTEM_TIME AS OF s.`event_time` AS ti
      ON s.remote_ip = ti.`indicator`
    LEFT JOIN `asset_inventory` FOR SYSTEM_TIME AS OF s.`event_time` AS a
      ON s.asset_key = a.`asset_id`
  ) AS j
) AS r
WHERE rule_name IS NOT NULL;
