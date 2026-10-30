"""Loads enrichment reference data into Confluent Cloud.

  threat_intel     <- data/threat_intel.csv (curated demo indicators)
                      + public ad/tracker watchlist data/ad_servers.csv (MVPS hosts list, bundled;
                        WATCHLIST_URL optionally downloads a newer copy instead)
  asset_inventory  <- data/asset_inventory.csv (each asset keyed by IP *and* by hostname)

The tables (and their Avro key/value schemas) are created by Flink DDL; this loader serializes
with the latest registered schemas, so Flink stays the owner of the table definition.

Usage:
  python reference_loader.py load
  python reference_loader.py add-indicator <indicator> <ip|domain> <category> <severity> "<name>"
"""

import csv
import io
import os
import sys
import time
import urllib.request

from confluent_kafka import SerializingProducer
from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def topic(table):
    """Topics / Flink tables carry the demo id: threat_intel -> threat_intel_<DEMO_ID>."""
    return f"{table}_{env('DEMO_ID')}"


def env(name):
    value = os.getenv(name)
    if not value:
        sys.exit(f"missing environment variable {name} (did scripts/01-provision-cloud.sh write docker/.env?)")
    return value


def schema_registry():
    return SchemaRegistryClient({
        "url": env("SCHEMA_REGISTRY_URL"),
        "basic.auth.user.info": f"{env('SCHEMA_REGISTRY_API_KEY')}:{env('SCHEMA_REGISTRY_API_SECRET')}",
    })


def wait_for_subject(sr, subject, timeout=600):
    deadline = time.time() + timeout
    while True:
        try:
            return sr.get_latest_version(subject).schema.schema_str
        except Exception as exc:  # subject appears once the Flink DDL has run
            if time.time() > deadline:
                sys.exit(f"schema subject {subject} not found: {exc}")
            print(f"waiting for {subject} (created by the Flink DDL) ...", flush=True)
            time.sleep(10)


def producer_for(sr, table, key_field):
    serializer_conf = {"auto.register.schemas": False, "use.latest.version": True}
    value_serializer = AvroSerializer(sr, wait_for_subject(sr, f"{topic(table)}-value"), conf=serializer_conf)
    # the primary key is an Avro record with one field, e.g. {"indicator": "1.2.3.4"}
    key_avro = AvroSerializer(sr, wait_for_subject(sr, f"{topic(table)}-key"), conf=serializer_conf)

    def key_serializer(key, ctx):
        return key_avro({key_field: key}, ctx)

    return SerializingProducer({
        "bootstrap.servers": env("KAFKA_BOOTSTRAP"),
        "security.protocol": os.getenv("KAFKA_SECURITY_PROTOCOL", "SASL_SSL"),
        "sasl.mechanisms": "PLAIN",
        "sasl.username": env("KAFKA_API_KEY"),
        "sasl.password": env("KAFKA_API_SECRET"),
        "client.id": f"siem-{os.getenv('DEMO_ID', 'local')}-reference-loader",
        "linger.ms": 100,
        "key.serializer": key_serializer,
        "value.serializer": value_serializer,
    })


def none_if_empty(row):
    return {k: (v if v != "" else None) for k, v in row.items()}


def threat_rows():
    with open(os.path.join(DATA_DIR, "threat_intel.csv")) as f:
        for row in csv.DictReader(f):
            row = none_if_empty(row)
            row["confidence"] = int(row["confidence"]) if row["confidence"] else None
            yield row

    body = None
    url = os.getenv("WATCHLIST_URL")
    if url:
        print(f"downloading public watchlist {url}", flush=True)
        try:
            body = urllib.request.urlopen(url, timeout=60).read().decode("utf-8", "replace")
        except Exception as exc:
            print(f"WARN: watchlist download failed ({exc}); using the bundled copy", flush=True)
    if body is None:
        with open(os.path.join(DATA_DIR, "ad_servers.csv"), encoding="utf-8") as f:
            body = f.read()
    seen = set()
    for row in csv.DictReader(io.StringIO(body)):
        domain = (row.get("domain") or "").strip().lower()
        if not domain or domain in seen:
            continue
        seen.add(domain)
        yield {
            "indicator": domain, "indicator_type": "domain", "threat_category": "adware",
            "threat_name": "Ad / tracking server (public hosts watchlist)", "severity": "low",
            "confidence": 50, "feed": "mvps-hosts watchlist", "country_iso": None, "geo_location": None,
        }


def asset_rows():
    with open(os.path.join(DATA_DIR, "asset_inventory.csv")) as f:
        for row in csv.DictReader(f):
            row = none_if_empty(row)
            yield {"asset_id": row["ip"], **row}
            yield {"asset_id": row["hostname"], **row}


def produce(producer, table, key_field, rows):
    count = 0
    for row in rows:
        producer.produce(topic=topic(table), key=row[key_field], value=row)
        producer.poll(0)
        count += 1
    remaining = producer.flush(60)
    if remaining:
        sys.exit(f"{remaining} messages to {topic(table)} were not delivered")
    print(f"loaded {count} rows into {topic(table)}", flush=True)


def load():
    sr = schema_registry()
    produce(producer_for(sr, "asset_inventory", "asset_id"), "asset_inventory", "asset_id", asset_rows())
    produce(producer_for(sr, "threat_intel", "indicator"), "threat_intel", "indicator", threat_rows())


def add_indicator(indicator, indicator_type, category, severity, name):
    sr = schema_registry()
    row = {
        "indicator": indicator.lower(), "indicator_type": indicator_type, "threat_category": category,
        "threat_name": name, "severity": severity, "confidence": 90, "feed": "analyst (live demo)",
        "country_iso": None, "geo_location": None,
    }
    produce(producer_for(sr, "threat_intel", "indicator"), "threat_intel", "indicator", [row])


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "load"
    if cmd == "load":
        load()
    elif cmd == "add-indicator" and len(sys.argv) == 7:
        add_indicator(*sys.argv[2:7])
    else:
        sys.exit(__doc__)
