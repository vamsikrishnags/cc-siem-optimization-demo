# Zeek network sensor that sniffs a dummy interface fed by tcpreplay (native arm64 + amd64).
FROM zeek/zeek:8.0.10

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tcpreplay iproute2 \
 && rm -rf /var/lib/apt/lists/*

COPY demo.zeek long-connections.zeek rotate-delete.sh start.sh /opt/demo/
RUN chmod +x /opt/demo/*.sh

WORKDIR /logs
ENTRYPOINT ["/opt/demo/start.sh"]
