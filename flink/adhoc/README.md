# Ad-hoc Flink SQL for the live demo

Run these in a Flink SQL workspace (Confluent Cloud UI → Environment → Flink → Open SQL workspace),
with the catalog set to the demo environment and the database set to the demo cluster.

Tables in Confluent Cloud carry the demo id (`syslog_raw_<DEMO_ID>`, `siem_events_<DEMO_ID>`, ...), while this
file uses the short names. Print a ready-to-paste copy with your names:

```bash
./scripts/07-flink-sql.sh
```
