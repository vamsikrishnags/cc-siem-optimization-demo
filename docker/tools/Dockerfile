# One small Python image for every helper: syslog generator, reference-data loader,
# Elastic/Kibana/Connect setup, and the Tableflow (Iceberg) lake query.
FROM python:3.12-slim-bookworm

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && python -c "import duckdb; c = duckdb.connect(); [c.install_extension(e) for e in ('httpfs', 'iceberg', 'avro', 'azure')]"

WORKDIR /app
COPY . /app
ENV PYTHONUNBUFFERED=1
