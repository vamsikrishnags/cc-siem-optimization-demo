"""One-shot setup for the local SIEM side:
  1. Elasticsearch index templates (ECS-style mappings for siem_events + pipeline_metrics)
  2. Kibana data views + dashboard (saved-objects import)
  3. Confluent Elasticsearch Sink connector on the local Kafka Connect worker
"""

import glob
import json
import os
import string
import sys
import time
import urllib.error
import urllib.request

ES = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
KIBANA = os.getenv("KIBANA_URL", "http://kibana:5601")
CONNECT = os.getenv("CONNECT_URL", "http://connect:8083")
CONFIG = os.getenv("CONFIG_DIR", "/config")
CONNECTOR_NAME = "siem-elasticsearch-sink"


def request(method, url, body=None, headers=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        text = resp.read().decode()
        return json.loads(text) if text else {}


def wait_for(name, url, ok=lambda r: True, timeout=600):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if ok(request("GET", url)):
                print(f"{name} is up", flush=True)
                return
        except Exception:
            pass
        print(f"waiting for {name} ...", flush=True)
        time.sleep(5)
    sys.exit(f"{name} did not become ready at {url}")


def elastic_templates():
    wait_for("Elasticsearch", f"{ES}/_cluster/health", lambda r: r.get("status") in ("green", "yellow"))
    for path in sorted(glob.glob(f"{CONFIG}/elastic/index-templates/*.json")):
        name = os.path.splitext(os.path.basename(path))[0]
        with open(path) as f:
            request("PUT", f"{ES}/_index_template/{name}", json.load(f))
        print(f"index template {name} installed", flush=True)


def kibana_objects():
    wait_for("Kibana", f"{KIBANA}/api/status",
             lambda r: r.get("status", {}).get("overall", {}).get("level") == "available")
    path = f"{CONFIG}/kibana/siem-dashboard.ndjson"
    boundary = "----siemdemo"
    with open(path, "rb") as f:
        payload = f.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"siem-dashboard.ndjson\"\r\n"
            f"Content-Type: application/ndjson\r\n\r\n").encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    result = request("POST", f"{KIBANA}/api/saved_objects/_import?overwrite=true", raw=body,
                     headers={"kbn-xsrf": "true", "Content-Type": f"multipart/form-data; boundary={boundary}"})
    if not result.get("success"):
        sys.exit(f"Kibana import failed: {json.dumps(result.get('errors'), indent=2)}")
    print(f"Kibana: imported {result.get('successCount')} saved objects", flush=True)
    request("POST", f"{KIBANA}/api/kibana/settings", {"changes": {"defaultIndex": "siem-events-dv"}},
            headers={"kbn-xsrf": "true", "Content-Type": "application/json"})


def sink_connector():
    wait_for("Kafka Connect", f"{CONNECT}/connector-plugins",
             lambda r: any("ElasticsearchSinkConnector" in p.get("class", "") for p in r))
    with open(f"{CONFIG}/connect/elasticsearch-sink.json") as f:
        template = string.Template(f.read())
    config = json.loads(template.substitute({
        "VALUE_CONVERTER": os.getenv("VALUE_CONVERTER", "io.confluent.connect.avro.AvroConverter"),
        "SCHEMA_REGISTRY_URL": os.getenv("SCHEMA_REGISTRY_URL", ""),
        "SCHEMA_REGISTRY_API_KEY": os.getenv("SCHEMA_REGISTRY_API_KEY", ""),
        "SCHEMA_REGISTRY_API_SECRET": os.getenv("SCHEMA_REGISTRY_API_SECRET", ""),
    }))
    request("PUT", f"{CONNECT}/connectors/{CONNECTOR_NAME}/config", config)
    for _ in range(30):
        time.sleep(3)
        try:
            status = request("GET", f"{CONNECT}/connectors/{CONNECTOR_NAME}/status")
        except urllib.error.HTTPError:
            continue
        states = [status["connector"]["state"]] + [t["state"] for t in status.get("tasks", [])]
        print(f"connector {CONNECTOR_NAME}: {states}", flush=True)
        if status.get("tasks") and all(s == "RUNNING" for s in states):
            return
        if "FAILED" in states:
            trace = next((t.get("trace", "") for t in status.get("tasks", []) if t["state"] == "FAILED"), "")
            sys.exit(f"connector failed:\n{trace[:2000]}")
    print("WARN: connector not RUNNING yet - check: curl localhost:8083/connectors/siem-elasticsearch-sink/status")


if __name__ == "__main__":
    steps = sys.argv[1:] or ["elastic", "kibana", "connector"]
    if "elastic" in steps:
        elastic_templates()
    if "kibana" in steps:
        kibana_objects()
    if "connector" in steps:
        sink_connector()
    print("SIEM setup complete: Kibana -> http://localhost:5601/app/dashboards#/view/siem-optimization", flush=True)
