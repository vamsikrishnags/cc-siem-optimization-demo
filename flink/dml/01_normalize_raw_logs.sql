-- =====================================================================================
-- Stage 1 - NORMALIZE
-- Schemaless JSON written by Fluent Bit (raw topics: `key`/`val` BYTES) becomes typed,
-- Schema Registry-governed Avro tables. Nothing is dropped here: these tables are the
-- full-fidelity copy that Tableflow keeps as Iceberg tables.
-- =====================================================================================
EXECUTE STATEMENT SET
BEGIN

-- ---------------------------- Zeek conn.log ----------------------------
INSERT INTO `zeek_conn`
SELECT
  JSON_VALUE(j, '$.uid'),
  ingest_time,
  JSON_VALUE(j, '$.ts' RETURNING DOUBLE),
  JSON_VALUE(j, '$.sensor'),
  JSON_VALUE(j, '$.id_orig_h'),
  JSON_VALUE(j, '$.id_orig_p' RETURNING INT),
  JSON_VALUE(j, '$.id_resp_h'),
  JSON_VALUE(j, '$.id_resp_p' RETURNING INT),
  JSON_VALUE(j, '$.proto'),
  JSON_VALUE(j, '$.service'),
  JSON_VALUE(j, '$.duration' RETURNING DOUBLE),
  TRY_CAST(JSON_VALUE(j, '$.orig_bytes') AS BIGINT),
  TRY_CAST(JSON_VALUE(j, '$.resp_bytes') AS BIGINT),
  JSON_VALUE(j, '$.conn_state'),
  JSON_VALUE(j, '$.local_orig' RETURNING BOOLEAN),
  JSON_VALUE(j, '$.local_resp' RETURNING BOOLEAN),
  JSON_VALUE(j, '$.history'),
  TRY_CAST(JSON_VALUE(j, '$.orig_pkts') AS BIGINT),
  TRY_CAST(JSON_VALUE(j, '$.resp_pkts') AS BIGINT),
  j
FROM (SELECT CAST(`val` AS STRING) AS j, `$rowtime` AS ingest_time FROM `zeek_conn_raw`);

-- ---------------------------- Zeek dns.log -----------------------------
INSERT INTO `zeek_dns`
SELECT
  JSON_VALUE(j, '$.uid'),
  ingest_time,
  JSON_VALUE(j, '$.ts' RETURNING DOUBLE),
  JSON_VALUE(j, '$.sensor'),
  JSON_VALUE(j, '$.id_orig_h'),
  JSON_VALUE(j, '$.id_orig_p' RETURNING INT),
  JSON_VALUE(j, '$.id_resp_h'),
  JSON_VALUE(j, '$.id_resp_p' RETURNING INT),
  JSON_VALUE(j, '$.proto'),
  -- lower-case and strip the resolver search suffix so lookups match the watchlist
  REGEXP_REPLACE(LOWER(JSON_VALUE(j, '$.query')), '\.localdomain$', ''),
  JSON_VALUE(j, '$.qtype_name'),
  JSON_VALUE(j, '$.rcode_name'),
  JSON_QUERY(j, '$.answers'),
  JSON_VALUE(j, '$.rejected' RETURNING BOOLEAN),
  j
FROM (SELECT CAST(`val` AS STRING) AS j, `$rowtime` AS ingest_time FROM `zeek_dns_raw`);

-- ---------------------------- Zeek http.log ----------------------------
INSERT INTO `zeek_http`
SELECT
  JSON_VALUE(j, '$.uid'),
  ingest_time,
  JSON_VALUE(j, '$.ts' RETURNING DOUBLE),
  JSON_VALUE(j, '$.sensor'),
  JSON_VALUE(j, '$.id_orig_h'),
  JSON_VALUE(j, '$.id_orig_p' RETURNING INT),
  JSON_VALUE(j, '$.id_resp_h'),
  JSON_VALUE(j, '$.id_resp_p' RETURNING INT),
  JSON_VALUE(j, '$.method'),
  LOWER(JSON_VALUE(j, '$.host')),
  JSON_VALUE(j, '$.uri'),
  JSON_VALUE(j, '$.referrer'),
  JSON_VALUE(j, '$.user_agent'),
  JSON_VALUE(j, '$.status_code' RETURNING INT),
  TRY_CAST(JSON_VALUE(j, '$.request_body_len') AS BIGINT),
  TRY_CAST(JSON_VALUE(j, '$.response_body_len') AS BIGINT),
  JSON_QUERY(j, '$.resp_mime_types'),
  j
FROM (SELECT CAST(`val` AS STRING) AS j, `$rowtime` AS ingest_time FROM `zeek_http_raw`);

-- ------------------- Syslog (unstructured text -> fields) -------------------
-- Fluent Bit's syslog-rfc3164 parser gives us pri/host/ident/pid/message; Flink parses
-- the free-text message per event type with regular expressions.
INSERT INTO `syslog_events`
SELECT
  `host`,
  ingest_time,
  `app`,
  `pid`,
  CAST(FLOOR(`pri` / 8) AS INT),
  MOD(`pri`, 8),
  `event_type`,
  -- action
  CASE `event_type`
    WHEN 'firewall'       THEN REGEXP_EXTRACT(msg, 'ACTION=([A-Z]+)', 1)
    WHEN 'authentication' THEN
      CASE
        WHEN msg LIKE 'Failed password%'   THEN 'login_failed'
        WHEN msg LIKE 'Accepted %'         THEN 'login_success'
        WHEN msg LIKE 'Invalid user%'      THEN 'invalid_user'
        WHEN msg LIKE '%session opened%'   THEN 'session_opened'
        WHEN msg LIKE '%session closed%'   THEN 'session_closed'
        ELSE 'other'
      END
    WHEN 'privilege'      THEN 'sudo'
    WHEN 'iam'            THEN
      CASE
        WHEN msg LIKE 'new user%'          THEN 'user_created'
        WHEN msg LIKE 'delete user%'       THEN 'user_deleted'
        WHEN msg LIKE '%to group%'         THEN 'group_membership_changed'
        ELSE 'iam_change'
      END
    WHEN 'account'        THEN
      CASE
        WHEN msg LIKE 'password reset%'    THEN 'password_reset'
        WHEN msg LIKE 'MFA%'               THEN 'mfa_change'
        ELSE 'account_change'
      END
    ELSE `app`
  END,
  -- src_ip
  CASE `event_type`
    WHEN 'firewall'       THEN REGEXP_EXTRACT(msg, 'SRC=([0-9a-fA-F:.]+)', 1)
    WHEN 'authentication' THEN REGEXP_EXTRACT(msg, 'from ([0-9a-fA-F:.]+) port', 1)
    WHEN 'account'        THEN REGEXP_EXTRACT(msg, 'from ([0-9a-fA-F:.]+)', 1)
  END,
  -- src_port
  TRY_CAST(CASE `event_type`
    WHEN 'firewall'       THEN REGEXP_EXTRACT(msg, 'SPT=([0-9]+)', 1)
    WHEN 'authentication' THEN REGEXP_EXTRACT(msg, ' port ([0-9]+)', 1)
  END AS INT),
  -- dst_ip
  CASE WHEN `event_type` = 'firewall' THEN REGEXP_EXTRACT(msg, 'DST=([0-9a-fA-F:.]+)', 1) END,
  -- dst_port
  TRY_CAST(CASE `event_type`
    WHEN 'firewall'       THEN REGEXP_EXTRACT(msg, 'DPT=([0-9]+)', 1)
    WHEN 'authentication' THEN '22'
  END AS INT),
  -- proto
  CASE `event_type`
    WHEN 'firewall'       THEN LOWER(REGEXP_EXTRACT(msg, 'PROTO=([A-Za-z]+)', 1))
    WHEN 'authentication' THEN 'tcp'
  END,
  -- user_name (PII - kept in the lake, pseudonymized before the SIEM)
  CASE `event_type`
    WHEN 'authentication' THEN COALESCE(REGEXP_EXTRACT(msg, 'for (invalid user )?([^ ]+) from', 2),
                                        REGEXP_EXTRACT(msg, 'for user ([^ (]+)', 1))
    WHEN 'privilege'      THEN REGEXP_EXTRACT(msg, '^ *([^ ]+) : ', 1)
    WHEN 'iam'            THEN REGEXP_EXTRACT(msg, 'name=([^,]+)', 1)
    WHEN 'account'        THEN REGEXP_EXTRACT(msg, 'for ([^ ]+@[^ ]+)', 1)
    ELSE REGEXP_EXTRACT(msg, 'of [uU]ser ([^ .]+)', 1)
  END,
  msg,
  j
FROM (
  SELECT
    j,
    ingest_time,
    `host`,
    `app`,
    `pid`,
    `pri`,
    msg,
    CASE
      WHEN `app` = 'kernel' AND msg LIKE '%ACTION=%'                      THEN 'firewall'
      WHEN `app` = 'sshd'                                                 THEN 'authentication'
      WHEN `app` = 'sudo'                                                 THEN 'privilege'
      WHEN `app` IN ('useradd', 'userdel', 'usermod', 'groupadd', 'gpasswd') THEN 'iam'
      WHEN `app` = 'account-service'                                      THEN 'account'
      ELSE 'system'
    END AS `event_type`
  FROM (
    SELECT
      j,
      ingest_time,
      JSON_VALUE(j, '$.host')                AS `host`,
      JSON_VALUE(j, '$.ident')               AS `app`,
      TRY_CAST(JSON_VALUE(j, '$.pid') AS INT) AS `pid`,
      TRY_CAST(JSON_VALUE(j, '$.pri') AS INT) AS `pri`,
      JSON_VALUE(j, '$.message')             AS msg
    FROM (SELECT CAST(`val` AS STRING) AS j, `$rowtime` AS ingest_time FROM `syslog_raw`)
  )
);

END;
