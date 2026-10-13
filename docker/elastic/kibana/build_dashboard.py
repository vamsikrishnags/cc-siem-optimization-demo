"""Generates siem-dashboard.ndjson (Kibana 8.19 saved objects) for the SIEM optimization demo.

    python3 docker/elastic/kibana/build_dashboard.py

Objects: 2 data views, 9 Lens visualizations, 1 markdown panel, 1 saved search, 1 dashboard.
"""

import json
import os

SIEM_DV = "siem-events-dv"
METRICS_DV = "pipeline-metrics-dv"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "siem-dashboard.ndjson")


# --------------------------------------------------------------------------- column helpers
def count(label="Events"):
    return {"label": label, "customLabel": True, "dataType": "number", "operationType": "count",
            "isBucketed": False, "scale": "ratio", "sourceField": "___records___", "params": {"emptyAsNull": True}}


def total(field, label, kql=None):
    col = {"label": label, "customLabel": True, "dataType": "number", "operationType": "sum",
           "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {"emptyAsNull": False}}
    if kql:
        col["filter"] = {"query": kql, "language": "kuery"}
    return col


def terms(field, order_col, size=10, label=None, other=False):
    return {"label": label or f"Top values of {field}", "customLabel": bool(label), "dataType": "string",
            "operationType": "terms", "isBucketed": True, "scale": "ordinal", "sourceField": field,
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_col},
                       "orderDirection": "desc", "otherBucket": other, "missingBucket": False,
                       "parentFormat": {"id": "terms"}}}


def histogram(field):
    return {"label": field, "dataType": "date", "operationType": "date_histogram", "isBucketed": True,
            "scale": "interval", "sourceField": field,
            "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}


def reduction_formula():
    """1 - siem/ingested, as Lens stores formulas (formula column + hidden math/sum columns)."""
    text = "1 - sum(event_count, kql='stage : \"siem\"') / sum(event_count, kql='stage : \"ingested\"')"
    siem_ref = "sum(event_count, kql='stage : \"siem\"')"
    ingested_ref = "sum(event_count, kql='stage : \"ingested\"')"
    div_start = text.index(siem_ref)
    divide = {"type": "function", "name": "divide", "args": ["redX0", "redX1"],
              "location": {"min": div_start, "max": len(text)}, "text": text[div_start:]}
    ast = {"type": "function", "name": "subtract", "args": [1, divide],
           "location": {"min": 0, "max": len(text)}, "text": text}
    part = "Part of Volume reduction"
    return {
        "red": {"label": "Volume reduction", "customLabel": True, "dataType": "number", "operationType": "formula",
                "isBucketed": False, "scale": "ratio", "references": ["redX2"],
                "params": {"formula": text, "isFormulaBroken": False,
                           "format": {"id": "percent", "params": {"decimals": 1}}}},
        "redX0": {**total("event_count", part, 'stage : "siem"'), "params": {"emptyAsNull": False}},
        "redX1": {**total("event_count", part, 'stage : "ingested"'), "params": {"emptyAsNull": False}},
        "redX2": {"label": part, "customLabel": True, "dataType": "number", "operationType": "math",
                  "isBucketed": False, "scale": "ratio", "references": ["redX0", "redX1"],
                  "params": {"tinymathAst": ast}},
    }


# --------------------------------------------------------------------------- lens object helpers
def lens(obj_id, title, dv, vis_type, columns, column_order, visualization, query="", description=""):
    # Lens expects bucket (group-by) columns before metric columns
    column_order = sorted(column_order, key=lambda c: not columns[c].get("isBucketed", False))
    return {
        "id": obj_id, "type": "lens",
        "attributes": {
            "title": title, "description": description, "visualizationType": vis_type,
            "state": {
                "datasourceStates": {"formBased": {"layers": {"layer1": {
                    "columns": columns, "columnOrder": column_order, "incompleteColumns": {}}}}},
                "visualization": visualization,
                "query": {"query": query, "language": "kuery"},
                "filters": [], "internalReferences": [], "adHocDataViews": {},
            },
        },
        "references": [{"type": "index-pattern", "id": dv, "name": "indexpattern-datasource-layer-layer1"}],
    }


def metric(obj_id, title, dv, columns, metric_col, order=None, query="", color=None):
    vis = {"layerId": "layer1", "layerType": "data", "metricAccessor": metric_col}
    if color:
        vis["color"] = color
    return lens(obj_id, title, dv, "lnsMetric", columns, order or list(columns), vis, query)


def xy(obj_id, title, dv, columns, x, ys, split=None, series="bar_stacked", query="", horizontal=False):
    layer = {"layerId": "layer1", "layerType": "data", "seriesType": series, "xAccessor": x, "accessors": ys}
    if split:
        layer["splitAccessor"] = split
    vis = {"preferredSeriesType": series, "layers": [layer],
           "legend": {"isVisible": True, "position": "right"}, "valueLabels": "hide",
           "fittingFunction": "Linear", "axisTitlesVisibilitySettings": {"x": False, "yLeft": False, "yRight": True}}
    if horizontal:
        vis["preferredSeriesType"] = layer["seriesType"] = "bar_horizontal"
    return lens(obj_id, title, dv, "lnsXY", columns, list(columns), vis, query)


def pie(obj_id, title, dv, columns, group, metric_col, query=""):
    vis = {"shape": "donut", "layers": [{"layerId": "layer1", "layerType": "data", "primaryGroups": [group],
                                         "metrics": [metric_col], "numberDisplay": "percent",
                                         "categoryDisplay": "default", "legendDisplay": "default",
                                         "nestedLegend": False}]}
    return lens(obj_id, title, dv, "lnsPie", columns, list(columns), vis, query)


def table(obj_id, title, dv, columns, query=""):
    vis = {"layerId": "layer1", "layerType": "data", "columns": [{"columnId": c} for c in columns]}
    return lens(obj_id, title, dv, "lnsDatatable", columns, list(columns), vis, query)


# --------------------------------------------------------------------------- objects
objects = [
    {"id": SIEM_DV, "type": "index-pattern",
     "attributes": {"title": "siem_events", "name": "SIEM events (Confluent curated)", "timeFieldName": "event_time"},
     "references": []},
    {"id": METRICS_DV, "type": "index-pattern",
     "attributes": {"title": "pipeline_metrics", "name": "Pipeline volume metrics", "timeFieldName": "metric_time"},
     "references": []},

    metric("lens-ingested", "Events ingested by Confluent", METRICS_DV,
           {"m": total("event_count", "Events ingested (all sources)")}, "m", query='stage : "ingested"'),
    metric("lens-siem", "Events forwarded to the SIEM", METRICS_DV,
           {"m": total("event_count", "Events forwarded to Elastic")}, "m", query='stage : "siem"', color="#E7664C"),
    metric("lens-reduction", "SIEM volume reduction", METRICS_DV,
           reduction_formula(), "red", order=["red", "redX0", "redX1", "redX2"], color="#54B399"),

    xy("lens-volume", "Ingested vs. forwarded to SIEM (events / minute)", METRICS_DV,
       {"x": histogram("metric_time"), "y": total("event_count", "Events"), "s": terms("stage", "y", 3, "Stage")},
       "x", ["y"], split="s", series="line"),
    xy("lens-alerts-time", "SIEM events over time by source", SIEM_DV,
       {"x": histogram("event_time"), "y": count(), "s": terms("event.dataset", "y", 5, "Source")},
       "x", ["y"], split="s"),
    xy("lens-rules", "Why events were kept (detection rule)", SIEM_DV,
       {"r": terms("event.rule", "y", 12, "Rule"), "y": count()}, "r", ["y"], horizontal=True),
    pie("lens-severity", "Severity", SIEM_DV,
        {"g": terms("event.severity_label", "m", 5, "Severity"), "m": count()}, "g", "m"),
    table("lens-threats", "Threat-intel matches (enrichment)", SIEM_DV,
          {"t": terms("threat.name", "c", 10, "Threat"), "h": terms("host.name", "c", 5, "Asset"),
           "o": terms("host.owner_team", "c", 3, "Owner team"), "c": count("Events")},
          query="threat.matched : true"),
    xy("lens-critical", "Tier-1 assets with high / critical events", SIEM_DV,
       {"h": terms("host.name", "y", 10, "Asset"), "y": count(), "s": terms("event.severity_label", "y", 4, "Severity")},
       "h", ["y"], split="s", horizontal=True, query='host.criticality : "tier1" and event.severity >= 3'),

    {"id": "md-story", "type": "visualization",
     "attributes": {
         "title": "About this dashboard", "description": "", "uiStateJSON": "{}",
         "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
         "visState": json.dumps({"title": "About this dashboard", "type": "markdown", "aggs": [], "params": {
             "fontSize": 11, "openLinksInNewTab": True, "markdown": (
                 "**Confluent SIEM optimization**\n\n"
                 "Zeek network logs and syslog stream from the laptop into **Confluent Cloud** (Fluent Bit). "
                 "**Flink SQL** normalizes every event, then forwards only security-relevant ones to Elastic - "
                 "**filtered**, **enriched** with threat intel and the asset inventory, and **PII-masked** "
                 "(`user.name` is a salted hash, e-mails are redacted).\n\n"
                 "The **full, unfiltered copy** of every log line is kept as **Apache Iceberg** tables by "
                 "**Tableflow** (Confluent-managed storage) - for forensics, compliance and analytics at object-storage cost.")}})},
     "references": []},

    {"id": "search-siem", "type": "search",
     "attributes": {
         "title": "SIEM events (enriched & masked)", "description": "",
         "columns": ["event.severity_label", "event.rule", "source.ip", "destination.domain", "user.name",
                     "host.name", "host.criticality", "threat.name", "message"],
         "sort": [["event_time", "desc"]], "grid": {}, "hideChart": True,
         "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({
             "query": {"query": "", "language": "kuery"}, "filter": [],
             "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index"})}},
     "references": [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": SIEM_DV}]},
]

# --------------------------------------------------------------------------- dashboard layout (48-col grid)
layout = [  # (panel id, saved object type, x, y, w, h)
    ("md-story", "visualization", 0, 0, 16, 11),
    ("lens-ingested", "lens", 16, 0, 11, 11),
    ("lens-siem", "lens", 27, 0, 10, 11),
    ("lens-reduction", "lens", 37, 0, 11, 11),
    ("lens-volume", "lens", 0, 11, 24, 13),
    ("lens-alerts-time", "lens", 24, 11, 24, 13),
    ("lens-rules", "lens", 0, 24, 20, 14),
    ("lens-severity", "lens", 20, 24, 10, 14),
    ("lens-critical", "lens", 30, 24, 18, 14),
    ("lens-threats", "lens", 0, 38, 20, 15),
    ("search-siem", "search", 20, 38, 28, 15),
]
panels, references = [], []
for i, (obj_id, obj_type, x, y, w, h) in enumerate(layout):
    pid = f"p{i}"
    panels.append({"type": obj_type, "panelIndex": pid, "gridData": {"x": x, "y": y, "w": w, "h": h, "i": pid},
                   "embeddableConfig": {"enhancements": {}}, "panelRefName": f"panel_{pid}"})
    references.append({"name": f"{pid}:panel_{pid}", "type": obj_type, "id": obj_id})

objects.append({
    "id": "siem-optimization", "type": "dashboard",
    "attributes": {
        "title": "Confluent SIEM Optimization", "description": "Filtered, enriched and masked SIEM feed from Confluent Cloud",
        "panelsJSON": json.dumps(panels),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "syncCursor": True, "syncTooltips": False,
                                   "hidePanelTitles": False}),
        "timeRestore": True, "timeFrom": "now-30m", "timeTo": "now",
        "refreshInterval": {"pause": False, "value": 10000},
        "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})},
    },
    "references": references,
})

# Saved-object versions of Kibana 8.19 - without them the import runs the oldest migrations and fails.
TYPE_VERSIONS = {"lens": "8.9.0", "dashboard": "10.3.0", "search": "10.5.0", "visualization": "8.5.0",
                 "index-pattern": "8.0.0"}
for obj in objects:
    obj["coreMigrationVersion"] = "8.8.0"
    obj["typeMigrationVersion"] = TYPE_VERSIONS[obj["type"]]

with open(OUT, "w") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")
print(f"wrote {len(objects)} saved objects to {OUT}")
