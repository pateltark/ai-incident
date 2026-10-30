-- CREATE DATABASE incident_copilot;
--
-- CREATE TABLE incident_copilot.application_logs (
--     id Int64,
--     service_id Int32,
--     level LowCardinality(String),
--     message String,
--     latency_ms Nullable(Int32),
--     request_id String,
--     timestamp DateTime64(3, 'UTC')
-- )
-- ENGINE = MergeTree()
-- ORDER BY (service_id, level, timestamp);

-- SELECT count() FROM incident_copilot.application_logs;

SELECT timestamp, service_name, level, message, latency_ms 
FROM incident_copilot.application_logs 
ORDER BY timestamp DESC 
LIMIT 100;

-- TRUNCATE TABLE incident_copilot.application_logs;

-- ALTER TABLE incident_copilot.application_logs ADD COLUMN service_name LowCardinality(String);