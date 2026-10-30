"""Hard-deletes the Schema Registry subjects that the demo's Flink tables registered.

Flink `CREATE TABLE` registers <table>-key / <table>-value subjects; the tables are named
<name>_<DEMO_ID>, so only this demo's subjects match. Terraform did not create them, and Schema
Registry belongs to the environment (not the cluster), so they survive `terraform destroy`.
Soft delete first, then permanent delete (Schema Registry requires both).

  python3 scripts/delete_schemas.py            # uses DEMO_ID + SCHEMA_REGISTRY_URL / _API_KEY / _API_SECRET from env
  python3 scripts/delete_schemas.py --dry-run
  DEMO_ID=k3x9q2 python3 scripts/delete_schemas.py --print-cli env-xxxxx   # no SR key left? print CLI commands
"""

import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

TABLES = ["threat_intel", "asset_inventory", "zeek_conn", "zeek_dns", "zeek_http", "syslog_events",
          "siem_events", "pipeline_metrics"]
DEMO_ID = os.environ.get("DEMO_ID", "")
if not DEMO_ID:
    sys.exit("DEMO_ID not set - e.g. DEMO_ID=k3x9q2 python3 scripts/delete_schemas.py ...")
SUBJECTS = [f"{t}_{DEMO_ID}-{part}" for t in TABLES for part in ("key", "value")]


def call(method, path):
    url = os.environ["SCHEMA_REGISTRY_URL"].rstrip("/") + path
    token = base64.b64encode(f"{os.environ['SCHEMA_REGISTRY_API_KEY']}:{os.environ['SCHEMA_REGISTRY_API_SECRET']}".encode()).decode()
    req = urllib.request.Request(url, method=method, headers={"Authorization": f"Basic {token}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode()
        return json.loads(body) if body else None


def main():
    args = sys.argv[1:]
    if args[:1] == ["--print-cli"]:
        env = args[1] if len(args) > 1 else "<env-id>"
        for s in SUBJECTS:
            print(f"confluent schema-registry schema delete --environment {env} --subject {s} --version all --force")
            print(f"confluent schema-registry schema delete --environment {env} --subject {s} --version all --permanent --force")
        return

    for var in ("SCHEMA_REGISTRY_URL", "SCHEMA_REGISTRY_API_KEY", "SCHEMA_REGISTRY_API_SECRET"):
        if not os.environ.get(var):
            sys.exit(f"{var} not set - run with --print-cli <env-id> to get Confluent CLI commands instead")

    dry_run = "--dry-run" in args
    existing = set(call("GET", "/subjects?deleted=true") or [])
    targets = [s for s in SUBJECTS if s in existing]
    if not targets:
        print("no demo schema subjects found")
        return

    for subject in targets:
        if dry_run:
            print(f"would hard-delete {subject}")
            continue
        quoted = urllib.parse.quote(subject, safe="")
        for suffix in ("", "?permanent=true"):
            try:
                call("DELETE", f"/subjects/{quoted}{suffix}")
            except urllib.error.HTTPError as exc:
                # 404 = already (soft-)deleted, which is fine for either step
                if exc.code != 404:
                    print(f"  ! {subject}{suffix}: HTTP {exc.code} {exc.read().decode()[:200]}")
        print(f"hard-deleted {subject}")


if __name__ == "__main__":
    main()
