# Self-managed Kafka Connect worker (runs on the laptop, stores its state in Confluent Cloud)
# with Confluent's Elasticsearch Service Sink connector.
FROM confluentinc/cp-kafka-connect:7.9.10

RUN confluent-hub install --no-prompt confluentinc/kafka-connect-elasticsearch:15.1.4
