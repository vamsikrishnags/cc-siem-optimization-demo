"""Query the Tableflow Iceberg tables (Confluent-managed storage) with DuckDB through Tableflow's
Iceberg REST catalog - proof that *every* log line is kept even though only a small, curated
fraction went to the SIEM.

  docker compose --profile tools run --rm lake-query                  # canned demo queries
  docker compose --profile tools run --rm lake-query python lake_query.py "SELECT ..."

Views zeek_conn, zeek_dns, zeek_http and syslog_events point at
lake."<cluster id>"."<topic>" (the catalog namespace is the Kafka cluster id; the topic - and so the
Iceberg table - is <name>_<DEMO_ID>, e.g. zeek_conn_k3x9q2).
"""

import json
import os
import sys
import urllib.request

import duckdb

ENDPOINT = os.environ.get("TABLEFLOW_CATALOG_ENDPOINT", "")
API_KEY = os.environ.get("TABLEFLOW_API_KEY", "")
API_SECRET = os.environ.get("TABLEFLOW_API_SECRET", "")
CLUSTER_ID = os.environ.get("KAFKA_CLUSTER_ID", "")
WAREHOUSE = os.environ.get("TABLEFLOW_WAREHOUSE", "warehouse")
DEMO_ID = os.environ.get("DEMO_ID", "")
TABLES = ["zeek_conn", "zeek_dns", "zeek_http", "syslog_events"]

DEMO_QUERIES = [
    ("Rows retained in the lake (100% of what was ingested)",
     """SELECT 'zeek_conn' AS table_name, COUNT(*) AS rows FROM zeek_conn
        UNION ALL SELECT 'zeek_dns', COUNT(*) FROM zeek_dns
        UNION ALL SELECT 'zeek_http', COUNT(*) FROM zeek_http
        UNION ALL SELECT 'syslog_events', COUNT(*) FROM syslog_events"""),
    ("Forensics: everything fin-ws-185 (192.168.1.185) resolved - incl. lookups the SIEM never received",
     """SELECT regexp_extract(query, '([^.]+\\.[^.]+)$', 1) AS registered_domain,
               COUNT(*) AS lookups, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
        FROM zeek_dns WHERE src_ip = '192.168.1.185'
        GROUP BY 1 ORDER BY lookups DESC LIMIT 10"""),
    ("Governed re-identification: real user names behind SSH failures (masked in the SIEM)",
     """SELECT user_name, src_ip, COUNT(*) AS failures
        FROM syslog_events WHERE event_type = 'authentication' AND action IN ('login_failed', 'invalid_user')
        GROUP BY 1, 2 ORDER BY failures DESC LIMIT 10"""),
    ("Long-term analytics: firewall decisions by hour (data that is too noisy/expensive for the SIEM)",
     """SELECT date_trunc('hour', event_time) AS hour, action, COUNT(*) AS events
        FROM syslog_events WHERE event_type = 'firewall'
        GROUP BY 1, 2 ORDER BY 1 DESC, 3 DESC LIMIT 12"""),
]


def connect():
    con = duckdb.connect()
    for ext in ("httpfs", "iceberg", "azure"):
        con.install_extension(ext)
        con.load_extension(ext)
    # Azure-hosted clusters: Tableflow's managed storage is ADLS; DuckDB's default Azure transport
    # can't find the CA bundle in slim Linux images, the curl transport uses the system one.
    con.execute("SET azure_transport_option_type = 'curl'")
    # Tableflow API key = OAuth2 client credentials; the catalog vends storage credentials.
    con.execute(f"""
        CREATE SECRET tableflow (
          TYPE ICEBERG,
          CLIENT_ID '{API_KEY}',
          CLIENT_SECRET '{API_SECRET}',
          ENDPOINT '{ENDPOINT}',
          OAUTH2_SCOPE 'catalog'
        )""")
    con.execute(f"ATTACH '{WAREHOUSE}' AS lake (TYPE iceberg, SECRET tableflow, ENDPOINT '{ENDPOINT}')")
    return con


def register(con):
    registered = []
    for table in TABLES:
        source = f'lake."{CLUSTER_ID}"."{table}_{DEMO_ID}"'
        try:
            con.execute(f"CREATE VIEW {table} AS SELECT * FROM {source}")
            con.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall()
        except duckdb.Error as exc:
            print(f"! {table}: not queryable yet ({str(exc).splitlines()[0][:160]})")
            con.execute(f"DROP VIEW IF EXISTS {table}")
            continue
        registered.append(table)
        print(f"registered {table:<14} -> {source}")
    return registered


def siem_count():
    try:
        with urllib.request.urlopen("http://elasticsearch:9200/siem_events/_count", timeout=5) as r:
            return json.load(r)["count"]
    except Exception:
        return None


def main():
    if not (ENDPOINT and API_KEY and API_SECRET and CLUSTER_ID and DEMO_ID):
        sys.exit("TABLEFLOW_CATALOG_ENDPOINT / TABLEFLOW_API_KEY / TABLEFLOW_API_SECRET / KAFKA_CLUSTER_ID / DEMO_ID "
                 "are not set (docker/.env is written by scripts/01-provision-cloud.sh)")
    con = connect()
    registered = register(con)
    if not registered:
        sys.exit("no Tableflow tables yet - Tableflow commits every few minutes; try again shortly")

    if len(sys.argv) > 1:
        print(con.sql(" ".join(sys.argv[1:])))
        return

    for title, sql in DEMO_QUERIES:
        print(f"\n=== {title}")
        try:
            print(con.sql(sql))
        except duckdb.Error as exc:
            print(f"(skipped: {str(exc).splitlines()[0]})")

    if len(registered) == len(TABLES):
        total = con.sql("SELECT " + " + ".join(f"(SELECT COUNT(*) FROM {t})" for t in TABLES)).fetchone()[0]
        siem = siem_count()
        if siem is not None and total:
            print(f"\n=== Lake vs SIEM: {total:,} events in Iceberg, {siem:,} in Elastic "
                  f"({100.0 * siem / total:.1f}% of the volume reached the SIEM)")


if __name__ == "__main__":
    main()
