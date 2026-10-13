#!/bin/sh
# Replays the reference pcap in an endless loop onto a dummy NIC and lets Zeek sniff it,
# so conn/dns/http logs are produced continuously with *current* timestamps.
set -eu

PCAP="${PCAP_FILE:-/pcaps/zeek_streamer.pcap}"
MULTIPLIER="${PCAP_REPLAY_MULTIPLIER:-1}"

if [ ! -s "$PCAP" ]; then
  echo "ERROR: $PCAP not found. Run scripts/02-start-local.sh (it downloads the pcap)." >&2
  exit 1
fi

IFACE=dummy0
if ip link show "$IFACE" >/dev/null 2>&1 || ip link add "$IFACE" type dummy 2>/dev/null; then
  ip link set "$IFACE" mtu 9000 up
else
  echo "WARN: cannot create dummy interface (needs NET_ADMIN); falling back to loopback" >&2
  IFACE=lo
fi

cd /logs
rm -f /logs/*.log

echo "Starting Zeek on $IFACE"
zeek -C -i "$IFACE" /opt/demo/demo.zeek &
ZEEK_PID=$!
sleep 5

echo "Replaying $PCAP on $IFACE in a loop (x$MULTIPLIER speed)"
tcpreplay -q --no-flow-stats -i "$IFACE" --loop=0 --multiplier="$MULTIPLIER" "$PCAP" &

trap 'kill $ZEEK_PID 2>/dev/null; exit 0' TERM INT
wait $ZEEK_PID
